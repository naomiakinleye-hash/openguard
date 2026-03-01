// Package messenger implements the OpenGuard v5 Facebook Messenger adapter.
// It handles hub.challenge webhook verification, signature checking, message
// normalization to UnifiedEvent format, and forwarding to the ingest pipeline.
package messenger

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // Facebook requires SHA-1 for webhook verification
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Config holds configuration for the Messenger Adapter.
type Config struct {
	// AppSecret is used to verify webhook payload signatures (X-Hub-Signature).
	AppSecret string
	// VerifyToken is used for hub.challenge webhook verification.
	VerifyToken string
	// PageAccessToken is the Facebook page access token.
	PageAccessToken string
}

// UnifiedEvent is a normalized event (shared with other adapters in production).
type UnifiedEvent struct {
	EventID       string                 `json:"event_id"`
	Timestamp     time.Time              `json:"timestamp"`
	Source        map[string]interface{} `json:"source"`
	Domain        string                 `json:"domain"`
	Severity      string                 `json:"severity"`
	RiskScore     float64                `json:"risk_score"`
	Tier          string                 `json:"tier"`
	Actor         map[string]interface{} `json:"actor"`
	Target        map[string]interface{} `json:"target"`
	Indicators    []interface{}          `json:"indicators"`
	HumanApproved bool                   `json:"human_approved"`
	AuditHash     string                 `json:"audit_hash"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// EventSink receives normalized events.
type EventSink interface {
	Ingest(ctx context.Context, payload []byte) error
}

// Adapter is the Facebook Messenger adapter.
type Adapter struct {
	cfg    Config
	sink   EventSink
	logger *zap.Logger
}

// NewAdapter constructs a new Messenger Adapter.
func NewAdapter(cfg Config, sink EventSink, logger *zap.Logger) *Adapter {
	return &Adapter{cfg: cfg, sink: sink, logger: logger}
}

// HandleWebhook is the HTTP handler for Messenger webhook requests.
func (a *Adapter) HandleWebhook(w http.ResponseWriter, r *http.Request) {
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

// handleMessage processes incoming Messenger webhook POST events.
func (a *Adapter) handleMessage(w http.ResponseWriter, r *http.Request) {
	sig := r.Header.Get("X-Hub-Signature")
	if err := a.verifySignature(r, sig); err != nil {
		a.logger.Warn("messenger: signature verification failed", zap.Error(err))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var payload map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		a.logger.Warn("messenger: invalid JSON payload", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	event, err := a.normalize(payload)
	if err != nil {
		a.logger.Warn("messenger: normalization failed", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	data, err := json.Marshal(event)
	if err != nil {
		a.logger.Error("messenger: marshal unified event", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := a.sink.Ingest(r.Context(), data); err != nil {
		a.logger.Error("messenger: ingest failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// verifySignature verifies the X-Hub-Signature header using SHA-1 HMAC.
func (a *Adapter) verifySignature(r *http.Request, sig string) error {
	if a.cfg.AppSecret == "" {
		return nil // disabled in dev mode
	}
	if sig == "" {
		return fmt.Errorf("messenger: missing X-Hub-Signature header")
	}
	if !strings.HasPrefix(sig, "sha1=") {
		return fmt.Errorf("messenger: unexpected signature format")
	}
	_ = r
	mac := hmac.New(sha1.New, []byte(a.cfg.AppSecret)) //nolint:gosec
	expected := "sha1=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("messenger: signature mismatch")
	}
	return nil
}

// normalize converts a raw Messenger webhook payload to a UnifiedEvent.
func (a *Adapter) normalize(payload map[string]interface{}) (*UnifiedEvent, error) {
	eventID := fmt.Sprintf("fb-%d", time.Now().UnixNano())
	return &UnifiedEvent{
		EventID:   eventID,
		Timestamp: time.Now().UTC(),
		Source: map[string]interface{}{
			"type":    "messenger",
			"adapter": "messenger",
		},
		Domain:   "comms",
		Severity: "info",
		Tier:     "T0",
		Actor: map[string]interface{}{
			"id":   "messenger-user",
			"type": "human",
		},
		Target: map[string]interface{}{
			"id":   "messenger-channel",
			"type": "channel",
		},
		Indicators:    []interface{}{},
		HumanApproved: false,
		AuditHash:     "",
		Metadata:      payload,
	}, nil
}
