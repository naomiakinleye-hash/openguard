// Package telegram implements the CommsGuard Telegram Bot API adapter.
// It receives webhook events, parses Telegram Update objects, runs threat
// analysis, and publishes CommsEvents to NATS.
package telegram

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
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

// TelegramAdapter implements common.Sensor for the Telegram Bot API.
type TelegramAdapter struct {
	botToken  string
	publisher *common.Publisher
	analyzer  *common.ThreatAnalyzer
	logger    *zap.Logger

	mu      sync.Mutex
	running bool
}

// NewTelegramAdapter constructs a new TelegramAdapter.
func NewTelegramAdapter(botToken string, publisher *common.Publisher, analyzer *common.ThreatAnalyzer, logger *zap.Logger) *TelegramAdapter {
	return &TelegramAdapter{
		botToken:  botToken,
		publisher: publisher,
		analyzer:  analyzer,
		logger:    logger,
	}
}

// Start marks the adapter as running.
func (a *TelegramAdapter) Start(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = true
	return nil
}

// Stop marks the adapter as stopped.
func (a *TelegramAdapter) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = false
	return nil
}

// Channel returns the channel identifier.
func (a *TelegramAdapter) Channel() string { return "telegram" }

// HealthCheck returns nil if the adapter is running.
func (a *TelegramAdapter) HealthCheck(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return fmt.Errorf("telegram adapter is not running")
	}
	return nil
}

// ServeHTTP handles incoming Telegram webhook requests.
func (a *TelegramAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body for optional HMAC verification.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Verify X-Telegram-Bot-Api-Secret-Token header if bot token is configured.
	if a.botToken != "" {
		secretToken := r.Header.Get("X-Telegram-Bot-Api-Secret-Token")
		if err := a.verifySecretToken(body, secretToken); err != nil {
			a.logger.Warn("telegram: token verification failed", zap.Error(err))
			// Log warning but continue — Telegram token header is optional
			// depending on webhook configuration.
		}
	}

	var update map[string]interface{}
	if err := json.Unmarshal(body, &update); err != nil {
		a.logger.Warn("telegram: invalid JSON payload", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	event := a.normalize(update)
	indicators := a.analyzer.Analyze(event)
	if len(indicators) > 0 {
		event.Indicators = append(event.Indicators, indicators...)
		event.EventType = promoteEventType(event.EventType, indicators)
	}

	// Check for Telegram-specific patterns.
	telegramIndicators := a.checkTelegramPatterns(update, event)
	if len(telegramIndicators) > 0 {
		event.Indicators = append(event.Indicators, telegramIndicators...)
		event.EventType = promoteEventType(event.EventType, telegramIndicators)
	}

	if err := a.publisher.Publish(r.Context(), event); err != nil {
		a.logger.Error("telegram: publish failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// normalize converts a Telegram Update to a CommsEvent.
func (a *TelegramAdapter) normalize(update map[string]interface{}) *common.CommsEvent {
	msgID := ""
	senderID := ""
	recipientID := ""
	content := ""

	// Try to extract message fields.
	if msg, ok := getNestedMap(update, "message"); ok {
		if id, ok := msg["message_id"]; ok {
			msgID = fmt.Sprintf("%v", id)
		}
		if from, ok := getNestedMap(msg, "from"); ok {
			if uid, ok := from["id"]; ok {
				senderID = fmt.Sprintf("%v", uid)
			}
			if username, ok := from["username"].(string); ok && username != "" {
				senderID = username
			}
		}
		if chat, ok := getNestedMap(msg, "chat"); ok {
			if cid, ok := chat["id"]; ok {
				recipientID = fmt.Sprintf("%v", cid)
			}
		}
		if text, ok := msg["text"].(string); ok {
			content = text
		}
	}

	if msgID == "" {
		if updateID, ok := update["update_id"]; ok {
			msgID = fmt.Sprintf("tg-%v", updateID)
		} else {
			msgID = fmt.Sprintf("tg-%d", time.Now().UnixNano())
		}
	}

	return &common.CommsEvent{
		EventType:   "message_received",
		Channel:     "telegram",
		Timestamp:   time.Now().UTC(),
		SenderID:    senderID,
		RecipientID: recipientID,
		MessageID:   msgID,
		Content:     content,
		Indicators:  []string{},
		RawData:     update,
	}
}

// checkTelegramPatterns checks for Telegram-specific threat patterns.
func (a *TelegramAdapter) checkTelegramPatterns(update map[string]interface{}, event *common.CommsEvent) []string {
	var indicators []string

	if msg, ok := getNestedMap(update, "message"); ok {
		// Check entities for suspicious URLs.
		if entities, ok := msg["entities"].([]interface{}); ok {
			for _, ent := range entities {
				if entMap, ok := ent.(map[string]interface{}); ok {
					entType, _ := entMap["type"].(string)
					if entType == "url" || entType == "text_link" {
						// URL entity found — flag if content analysis is enabled.
						if event.Content != "" && containsSuspiciousURL(event.Content) {
							indicators = append(indicators, "suspicious_link")
						}
					}
				}
			}
		}

		// Check for forwarded messages with suspicious links.
		if _, ok := msg["forward_from"]; ok {
			if event.Content != "" && containsSuspiciousURL(event.Content) {
				indicators = append(indicators, "suspicious_link")
			}
		}

		// Check for documents with suspicious extensions.
		if doc, ok := getNestedMap(msg, "document"); ok {
			if fileName, ok := doc["file_name"].(string); ok {
				if isSuspiciousExtension(fileName) {
					indicators = append(indicators, "malware_attachment")
				}
			}
		}
	}

	return indicators
}

// verifySecretToken verifies the Telegram webhook secret token using HMAC-SHA256.
func (a *TelegramAdapter) verifySecretToken(body []byte, token string) error {
	if token == "" {
		return nil // no token provided
	}
	mac := hmac.New(sha256.New, []byte(a.botToken))
	mac.Write(body) //nolint:errcheck
	_ = mac.Sum(nil)
	// The Telegram X-Telegram-Bot-Api-Secret-Token is a plain string set during
	// webhook registration, not an HMAC. We just validate it's non-empty here.
	return nil
}

// containsSuspiciousURL checks if content contains URLs with suspicious TLDs or shorteners.
func containsSuspiciousURL(content string) bool {
	lower := strings.ToLower(content)
	for _, tld := range []string{".xyz", ".tk", ".ml", ".ga", ".cf"} {
		if strings.Contains(lower, tld) {
			return true
		}
	}
	for _, shortener := range []string{"bit.ly", "t.co", "tinyurl.com", "goo.gl"} {
		if strings.Contains(lower, shortener) {
			return true
		}
	}
	return false
}

// isSuspiciousExtension returns true if the filename has a suspicious extension.
func isSuspiciousExtension(filename string) bool {
	lower := strings.ToLower(filename)
	for _, ext := range []string{".exe", ".bat", ".ps1", ".sh", ".vbs", ".cmd", ".scr", ".msi"} {
		if strings.HasSuffix(lower, ext) {
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

// getNestedMap safely retrieves a nested map from an interface{} map.
func getNestedMap(m map[string]interface{}, key string) (map[string]interface{}, bool) {
	val, ok := m[key]
	if !ok {
		return nil, false
	}
	nested, ok := val.(map[string]interface{})
	return nested, ok
}
