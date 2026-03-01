// Package whatsapp implements the OpenGuard v5 WhatsApp Business API adapter.
// It receives webhook events, verifies signatures, normalizes messages to
// UnifiedEvent format, and forwards them to the ingest pipeline.
package whatsapp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Config holds configuration for the WhatsApp Adapter.
type Config struct {
	// AppSecret is used to verify webhook payload signatures.
	AppSecret string
	// VerifyToken is used for webhook subscription verification.
	VerifyToken string
	// ListenAddr is the address for the webhook receiver.
	ListenAddr string
}

// UnifiedEvent is a normalized representation of any adapter event.
// In production this would be the shared type from a common package.
type UnifiedEvent struct {
	EventID     string                 `json:"event_id"`
	Timestamp   time.Time              `json:"timestamp"`
	Source      map[string]interface{} `json:"source"`
	Domain      string                 `json:"domain"`
	Severity    string                 `json:"severity"`
	RiskScore   float64                `json:"risk_score"`
	Tier        string                 `json:"tier"`
	Actor       map[string]interface{} `json:"actor"`
	Target      map[string]interface{} `json:"target"`
	Indicators  []interface{}          `json:"indicators"`
	HumanApproved bool                 `json:"human_approved"`
	AuditHash   string                 `json:"audit_hash"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// EventSink receives normalized events from the adapter.
type EventSink interface {
	Ingest(ctx context.Context, payload []byte) error
}

// Adapter is the WhatsApp Business API adapter.
type Adapter struct {
	cfg    Config
	sink   EventSink
	logger *zap.Logger

	mu          sync.Mutex
	seen        map[string]time.Time // deduplication cache
}

// NewAdapter constructs a new WhatsApp Adapter.
func NewAdapter(cfg Config, sink EventSink, logger *zap.Logger) *Adapter {
	return &Adapter{
		cfg:    cfg,
		sink:   sink,
		logger: logger,
		seen:   make(map[string]time.Time),
	}
}

// HandleWebhook is the HTTP handler for WhatsApp webhook POST requests.
func (a *Adapter) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Webhook verification challenge.
		a.handleVerification(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify signature.
	sig := r.Header.Get("X-Hub-Signature-256")
	if err := a.verifySignature(r, sig); err != nil {
		a.logger.Warn("whatsapp: signature verification failed", zap.Error(err))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		a.logger.Warn("whatsapp: invalid JSON payload", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	event, err := a.normalize(payload)
	if err != nil {
		a.logger.Warn("whatsapp: normalization failed", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Deduplication.
	if a.isDuplicate(event.EventID) {
		w.WriteHeader(http.StatusOK)
		return
	}

	data, err := json.Marshal(event)
	if err != nil {
		a.logger.Error("whatsapp: marshal unified event", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := a.sink.Ingest(r.Context(), data); err != nil {
		a.logger.Error("whatsapp: ingest failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// normalize converts a raw WhatsApp webhook payload to a UnifiedEvent.
func (a *Adapter) normalize(payload map[string]interface{}) (*UnifiedEvent, error) {
	msgID := extractString(payload, "entry", "0", "changes", "0", "value", "messages", "0", "id")
	if msgID == "" {
		msgID = fmt.Sprintf("wa-%d", time.Now().UnixNano())
	}
	from := extractString(payload, "entry", "0", "changes", "0", "value", "messages", "0", "from")

	return &UnifiedEvent{
		EventID:   msgID,
		Timestamp: time.Now().UTC(),
		Source: map[string]interface{}{
			"type":    "whatsapp",
			"adapter": "whatsapp",
		},
		Domain:   "comms",
		Severity: "info",
		Tier:     "T0",
		Actor: map[string]interface{}{
			"id":   from,
			"type": "human",
		},
		Target: map[string]interface{}{
			"id":   "whatsapp-channel",
			"type": "channel",
		},
		Indicators:    []interface{}{},
		HumanApproved: false,
		AuditHash:     "",
		Metadata:      payload,
	}, nil
}

// verifySignature checks the X-Hub-Signature-256 header.
func (a *Adapter) verifySignature(r *http.Request, sig string) error {
	if a.cfg.AppSecret == "" {
		return nil // signature check disabled in dev mode
	}
	if sig == "" {
		return fmt.Errorf("whatsapp: missing X-Hub-Signature-256 header")
	}
	_ = r // body reading for HMAC should happen before decode; simplified here.
	// In production: read body bytes, compute HMAC, compare.
	mac := hmac.New(sha256.New, []byte(a.cfg.AppSecret))
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("whatsapp: signature mismatch")
	}
	return nil
}

// handleVerification responds to the WhatsApp webhook verification challenge.
func (a *Adapter) handleVerification(w http.ResponseWriter, r *http.Request) {
	mode := r.URL.Query().Get("hub.mode")
	token := r.URL.Query().Get("hub.verify_token")
	challenge := r.URL.Query().Get("hub.challenge")
	if mode == "subscribe" && token == a.cfg.VerifyToken {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(challenge))
		return
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}

// isDuplicate returns true if the event ID was seen recently (dedup window: 5 minutes).
func (a *Adapter) isDuplicate(eventID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if t, ok := a.seen[eventID]; ok && time.Since(t) < 5*time.Minute {
		return true
	}
	a.seen[eventID] = time.Now()
	// Prune old entries.
	for k, v := range a.seen {
		if time.Since(v) > 5*time.Minute {
			delete(a.seen, k)
		}
	}
	return false
}

// extractString is a helper to safely extract nested string values from a map
// using a sequence of string keys as the path.
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
	// Handle numeric index strings like "0".
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
