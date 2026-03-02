// Package whatsapp implements the CommsGuard WhatsApp Business API adapter.
// It receives webhook events, verifies signatures, normalizes messages to
// CommsEvent format, runs threat analysis, and publishes to NATS.
package whatsapp

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

// WhatsAppAdapter implements common.Sensor for the WhatsApp Business API.
type WhatsAppAdapter struct {
	appSecret   string
	verifyToken string
	publisher   *common.Publisher
	analyzer    *common.ThreatAnalyzer
	logger      *zap.Logger

	mu      sync.Mutex
	running bool
}

// NewWhatsAppAdapter constructs a new WhatsAppAdapter.
func NewWhatsAppAdapter(appSecret, verifyToken string, publisher *common.Publisher, analyzer *common.ThreatAnalyzer, logger *zap.Logger) *WhatsAppAdapter {
	return &WhatsAppAdapter{
		appSecret:   appSecret,
		verifyToken: verifyToken,
		publisher:   publisher,
		analyzer:    analyzer,
		logger:      logger,
	}
}

// Start marks the adapter as running.
func (a *WhatsAppAdapter) Start(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = true
	return nil
}

// Stop marks the adapter as stopped.
func (a *WhatsAppAdapter) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = false
	return nil
}

// Channel returns the channel identifier.
func (a *WhatsAppAdapter) Channel() string { return "whatsapp" }

// HealthCheck returns nil if the adapter is running.
func (a *WhatsAppAdapter) HealthCheck(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return fmt.Errorf("whatsapp adapter is not running")
	}
	return nil
}

// ServeHTTP handles incoming WhatsApp webhook requests.
func (a *WhatsAppAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.handleVerification(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read body for HMAC verification.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Verify signature.
	sig := r.Header.Get("X-Hub-Signature-256")
	if err := a.verifySignature(body, sig); err != nil {
		a.logger.Warn("whatsapp: signature verification failed", zap.Error(err))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		a.logger.Warn("whatsapp: invalid JSON payload", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	event := a.normalize(payload)
	indicators := a.analyzer.Analyze(event)
	if len(indicators) > 0 {
		event.Indicators = append(event.Indicators, indicators...)
		event.EventType = promoteEventType(event.EventType, indicators)
	}

	if err := a.publisher.Publish(r.Context(), event); err != nil {
		a.logger.Error("whatsapp: publish failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// normalize converts a raw WhatsApp webhook payload to a CommsEvent.
func (a *WhatsAppAdapter) normalize(payload map[string]interface{}) *common.CommsEvent {
	msgID := extractString(payload, "entry", "0", "changes", "0", "value", "messages", "0", "id")
	if msgID == "" {
		msgID = fmt.Sprintf("wa-%d", time.Now().UnixNano())
	}
	from := extractString(payload, "entry", "0", "changes", "0", "value", "messages", "0", "from")
	to := extractString(payload, "entry", "0", "changes", "0", "value", "metadata", "phone_number_id")
	msgType := extractString(payload, "entry", "0", "changes", "0", "value", "messages", "0", "type")
	text := extractString(payload, "entry", "0", "changes", "0", "value", "messages", "0", "text", "body")

	indicators := []string{}
	// Check for suspicious document extensions.
	if msgType == "document" || msgType == "image" {
		fileName := extractString(payload, "entry", "0", "changes", "0", "value", "messages", "0", "document", "filename")
		if isSuspiciousExtension(fileName) {
			indicators = append(indicators, "malware_attachment")
		}
	}

	return &common.CommsEvent{
		EventType:   "message_received",
		Channel:     "whatsapp",
		Timestamp:   time.Now().UTC(),
		SenderID:    from,
		RecipientID: to,
		MessageID:   msgID,
		Content:     text,
		Indicators:  indicators,
		RawData:     payload,
	}
}

// verifySignature checks the X-Hub-Signature-256 header.
func (a *WhatsAppAdapter) verifySignature(body []byte, sig string) error {
	if a.appSecret == "" {
		return nil // disabled in dev mode
	}
	if sig == "" {
		return fmt.Errorf("whatsapp: missing X-Hub-Signature-256 header")
	}
	if !strings.HasPrefix(sig, "sha256=") {
		return fmt.Errorf("whatsapp: unexpected signature format")
	}
	mac := hmac.New(sha256.New, []byte(a.appSecret))
	mac.Write(body) //nolint:errcheck
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("whatsapp: signature mismatch")
	}
	return nil
}

// handleVerification responds to the WhatsApp webhook verification challenge.
func (a *WhatsAppAdapter) handleVerification(w http.ResponseWriter, r *http.Request) {
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

// extractString is a helper to safely extract nested string values from a map.
func extractString(m map[string]interface{}, keys ...string) string {
	if len(keys) == 0 || m == nil {
		return ""
	}
	val, ok := m[keys[0]]
	if !ok {
		return ""
	}
	if len(keys) == 1 {
		s, _ := val.(string)
		return s
	}
	switch v := val.(type) {
	case map[string]interface{}:
		return extractString(v, keys[1:]...)
	case []interface{}:
		if len(v) == 0 {
			return ""
		}
		if sub, ok := v[0].(map[string]interface{}); ok {
			return extractString(sub, keys[1:]...)
		}
	}
	return ""
}
