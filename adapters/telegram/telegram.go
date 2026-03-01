// Package telegram implements the OpenGuard v5 Telegram Bot API adapter.
// It supports both webhook and long-polling modes, normalizes messages to
// UnifiedEvent format, and forwards them to the ingest pipeline.
package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// Config holds configuration for the Telegram Adapter.
type Config struct {
	// BotToken is the Telegram bot token.
	BotToken string
	// WebhookMode enables webhook mode when true (default: long-polling).
	WebhookMode bool
	// ListenAddr is the address for the webhook receiver (webhook mode only).
	ListenAddr string
	// PollInterval is the long-polling interval (polling mode only).
	PollInterval time.Duration
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

// Adapter is the Telegram Bot adapter.
type Adapter struct {
	cfg    Config
	sink   EventSink
	logger *zap.Logger
}

// NewAdapter constructs a new Telegram Adapter.
func NewAdapter(cfg Config, sink EventSink, logger *zap.Logger) *Adapter {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Second
	}
	return &Adapter{cfg: cfg, sink: sink, logger: logger}
}

// HandleWebhook is the HTTP handler for Telegram webhook POST requests.
func (a *Adapter) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var update map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		a.logger.Warn("telegram: invalid JSON payload", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	event, err := a.normalize(update)
	if err != nil {
		a.logger.Warn("telegram: normalization failed", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	data, err := json.Marshal(event)
	if err != nil {
		a.logger.Error("telegram: marshal unified event", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if err := a.sink.Ingest(r.Context(), data); err != nil {
		a.logger.Error("telegram: ingest failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Poll runs a long-polling loop until ctx is cancelled.
func (a *Adapter) Poll(ctx context.Context) error {
	a.logger.Info("telegram: starting long-poll loop", zap.Duration("interval", a.cfg.PollInterval))
	ticker := time.NewTicker(a.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := a.poll(ctx); err != nil {
				a.logger.Warn("telegram: poll error", zap.Error(err))
			}
		}
	}
}

// poll fetches pending updates from the Telegram Bot API.
func (a *Adapter) poll(_ context.Context) error {
	// Stub: full implementation calls https://api.telegram.org/bot<token>/getUpdates
	return nil
}

// normalize converts a raw Telegram update to a UnifiedEvent.
func (a *Adapter) normalize(update map[string]interface{}) (*UnifiedEvent, error) {
	updateID := fmt.Sprintf("tg-%d", time.Now().UnixNano())
	if id, ok := update["update_id"]; ok {
		updateID = fmt.Sprintf("tg-%v", id)
	}
	return &UnifiedEvent{
		EventID:   updateID,
		Timestamp: time.Now().UTC(),
		Source: map[string]interface{}{
			"type":    "telegram",
			"adapter": "telegram",
		},
		Domain:   "comms",
		Severity: "info",
		Tier:     "T0",
		Actor: map[string]interface{}{
			"id":   "telegram-user",
			"type": "human",
		},
		Target: map[string]interface{}{
			"id":   "telegram-channel",
			"type": "channel",
		},
		Indicators:    []interface{}{},
		HumanApproved: false,
		AuditHash:     "",
		Metadata:      update,
	}, nil
}
