// Package messenger implements the CommsGuard Facebook Messenger adapter.
// It handles webhook verification, signature checking, message normalization
// to CommsEvent format, and publishing to NATS.
package messenger

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	"go.uber.org/zap"
)

// MessengerAdapter implements common.Sensor for the Facebook Messenger Platform.
type MessengerAdapter struct {
	appSecret   string
	verifyToken string
	publisher   *common.Publisher
	analyzer    *common.ThreatAnalyzer
	logger      *zap.Logger

	mu      sync.Mutex
	running bool
}

// NewMessengerAdapter constructs a new MessengerAdapter.
func NewMessengerAdapter(appSecret, verifyToken string, publisher *common.Publisher, analyzer *common.ThreatAnalyzer, logger *zap.Logger) *MessengerAdapter {
	return &MessengerAdapter{
		appSecret:   appSecret,
		verifyToken: verifyToken,
		publisher:   publisher,
		analyzer:    analyzer,
		logger:      logger,
	}
}

// Start marks the adapter as running.
func (a *MessengerAdapter) Start(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = true
	return nil
}

// Stop marks the adapter as stopped.
func (a *MessengerAdapter) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = false
	return nil
}

// Channel returns the channel identifier.
func (a *MessengerAdapter) Channel() string { return "messenger" }

// HealthCheck returns nil if the adapter is running.
func (a *MessengerAdapter) HealthCheck(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return fmt.Errorf("messenger adapter is not running")
	}
	return nil
}

// ServeHTTP handles incoming Facebook Messenger webhook requests.
func (a *MessengerAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.handleVerification(w, r)
	case http.MethodPost:
		a.handleMessage(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleVerification responds to the Facebook hub.challenge verification request.
func (a *MessengerAdapter) handleVerification(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("hub.mode")
	token := r.URL.Query().Get("hub.verify_token")
	challenge := r.URL.Query().Get("hub.challenge")
	if mode == "subscribe" && token == a.verifyToken {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(challenge))
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}

// handleMessage processes incoming Messenger webhook POST events.
func (a *MessengerAdapter) handleMessage(w http.ResponseWriter, r *http.Request) {
	// Read body for HMAC verification.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	sig := r.Header.Get("X-Hub-Signature-256")
	if err := a.verifySignature(body, sig); err != nil {
		a.logger.Warn("messenger: signature verification failed", zap.Error(err))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		a.logger.Warn("messenger: invalid JSON payload", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	events := a.normalize(payload)
	for _, event := range events {
		indicators := a.analyzer.Analyze(event)
		if len(indicators) > 0 {
			event.Indicators = append(event.Indicators, indicators...)
			event.EventType = promoteEventType(event.EventType, indicators)
		}

		if err := a.publisher.Publish(r.Context(), event); err != nil {
			a.logger.Error("messenger: publish failed", zap.Error(err))
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// normalize converts a Messenger webhook payload to one or more CommsEvents.
func (a *MessengerAdapter) normalize(payload map[string]interface{}) []*common.CommsEvent {
	var events []*common.CommsEvent

	entries, _ := payload["entry"].([]interface{})
	for _, e := range entries {
		entry, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		messagingList, _ := entry["messaging"].([]interface{})
		for _, m := range messagingList {
			msg, ok := m.(map[string]interface{})
			if !ok {
				continue
			}

			senderID := ""
			recipientID := ""
			msgID := ""
			content := ""

			if sender, ok := msg["sender"].(map[string]interface{}); ok {
				senderID, _ = sender["id"].(string)
			}
			if recipient, ok := msg["recipient"].(map[string]interface{}); ok {
				recipientID, _ = recipient["id"].(string)
			}

			if message, ok := msg["message"].(map[string]interface{}); ok {
				msgID, _ = message["mid"].(string)
				content, _ = message["text"].(string)
			}

			if msgID == "" {
				msgID = fmt.Sprintf("fb-%d", time.Now().UnixNano())
			}

			indicators := []string{}
			// Check attachments.
			if message, ok := msg["message"].(map[string]interface{}); ok {
				if attachments, ok := message["attachments"].([]interface{}); ok {
					for _, att := range attachments {
						if attMap, ok := att.(map[string]interface{}); ok {
							attType, _ := attMap["type"].(string)
							if payload, ok := attMap["payload"].(map[string]interface{}); ok {
								if url, ok := payload["url"].(string); ok {
									if isSuspiciousExtension(url) || attType == "file" {
										indicators = append(indicators, "malware_attachment")
									}
								}
							}
						}
					}
				}
			}

			events = append(events, &common.CommsEvent{
				EventType:   "message_received",
				Channel:     "messenger",
				Timestamp:   time.Now().UTC(),
				SenderID:    senderID,
				RecipientID: recipientID,
				MessageID:   msgID,
				Content:     content,
				Indicators:  indicators,
				RawData:     msg,
			})
		}
	}

	if len(events) == 0 {
		// Emit a generic event even if we can't parse the structure.
		events = append(events, &common.CommsEvent{
			EventType:  "message_received",
			Channel:    "messenger",
			Timestamp:  time.Now().UTC(),
			MessageID:  fmt.Sprintf("fb-%d", time.Now().UnixNano()),
			Indicators: []string{},
			RawData:    payload,
		})
	}

	return events
}

// verifySignature checks the X-Hub-Signature-256 header using HMAC-SHA256.
func (a *MessengerAdapter) verifySignature(body []byte, sig string) error {
	if a.appSecret == "" {
		return nil // disabled in dev mode
	}
	if sig == "" {
		return fmt.Errorf("messenger: missing X-Hub-Signature-256 header")
	}
	if !strings.HasPrefix(sig, "sha256=") {
		return fmt.Errorf("messenger: unexpected signature format")
	}
	mac := hmac.New(sha256.New, []byte(a.appSecret))
	mac.Write(body) //nolint:errcheck
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("messenger: signature mismatch")
	}
	return nil
}

// isSuspiciousExtension returns true if the filename/URL has a suspicious extension.
func isSuspiciousExtension(filename string) bool {
	lower := strings.ToLower(filename)
	for _, ext := range []string{".exe", ".bat", ".ps1", ".sh", ".vbs", ".cmd", ".scr", ".msi"} {
		if strings.HasSuffix(lower, ext) || strings.Contains(lower, ext+"?") {
			return true
		}
	}
	return false
}

// promoteEventType upgrades the event type based on detected indicators.
func promoteEventType(current string, indicators []string) string {
	for _, ind := range indicators {
		switch ind {
		case "malware_attachment":
			return "malware_attachment_detected"
		case "credential_harvesting":
			return "credential_harvesting_detected"
		case "data_exfiltration":
			return "data_exfiltration_detected"
		case "account_takeover":
			return "account_takeover_attempt"
		case "phishing":
			return "phishing_detected"
		case "social_engineering":
			return "social_engineering_detected"
		case "suspicious_link":
			return "suspicious_link_detected"
		case "bulk_message":
			return "bulk_message_detected"
		case "spam":
			return "spam_detected"
		}
	}
	return current
}
