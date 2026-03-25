// Package ingest implements the OpenGuard v5 event ingestion service.
// It receives raw events from all adapter channels, validates them against
// the unified-event schema, and publishes validated events to internal topics.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// Config holds configuration for the ingest Service.
type Config struct {
	// NATSUrl is the NATS server connection URL.
	NATSUrl string
	// SchemaPath is the path to the unified-event JSON schema file.
	SchemaPath string
	// InternalTopic is the NATS topic for validated events.
	InternalTopic string
	// DeadLetterTopic is the NATS topic for invalid/unprocessable events.
	DeadLetterTopic string
}

// EventHandler is called with each validated event.
type EventHandler interface {
	HandleEvent(ctx context.Context, event map[string]interface{}) error
}

// Service is the event ingestion service.
// It validates incoming events against the unified-event schema and routes
// them to the appropriate downstream handlers.
type Service struct {
	cfg     Config
	handler EventHandler
	logger  *zap.Logger
	schema  map[string]interface{}
	stopCh  chan struct{}
	nc      *nats.Conn
}

// NewService constructs a new ingest Service.
func NewService(cfg Config, handler EventHandler, _ interface{}, logger *zap.Logger) (*Service, error) {
	if cfg.InternalTopic == "" {
		cfg.InternalTopic = "openguard.events.validated"
	}
	if cfg.DeadLetterTopic == "" {
		cfg.DeadLetterTopic = "openguard.events.dlq"
	}

	svc := &Service{
		cfg:    cfg,
		handler: handler,
		logger: logger,
		stopCh: make(chan struct{}),
	}

	if err := svc.loadSchema(); err != nil {
		return nil, fmt.Errorf("ingest: load schema: %w", err)
	}

	return svc, nil
}

// Start begins the ingestion service, connecting to NATS if a URL is configured.
// When NATS is available it subscribes to all raw event topics so that
// standalone adapter agents (hostguard-agent, etc.) are consumed automatically.
func (s *Service) Start(ctx context.Context) error {
	if s.cfg.NATSUrl != "" {
		nc, err := nats.Connect(s.cfg.NATSUrl,
			nats.Name("openguard-ingest"),
			nats.MaxReconnects(-1),
		)
		if err != nil {
			s.logger.Warn("ingest: NATS connect failed (will run without message bus)",
				zap.String("url", s.cfg.NATSUrl), zap.Error(err))
		} else {
			s.nc = nc
			s.logger.Info("ingest: connected to NATS", zap.String("url", s.cfg.NATSUrl))
			// Subscribe to all raw event topics so agent-published events flow in.
			topics := []string{
				"openguard.hostguard.raw",
				"openguard.agentguard.raw",
				"openguard.commsguard.raw",
				"openguard.networkguard.raw",
			}
			for _, topic := range topics {
				topic := topic
				if _, subErr := nc.Subscribe(topic, func(msg *nats.Msg) {
					if ingestErr := s.Ingest(context.Background(), msg.Data); ingestErr != nil {
						s.logger.Warn("ingest: process nats message",
							zap.String("topic", topic), zap.Error(ingestErr))
					}
				}); subErr != nil {
					s.logger.Warn("ingest: subscribe failed",
						zap.String("topic", topic), zap.Error(subErr))
				}
			}
			s.logger.Info("ingest: subscribed to NATS topics", zap.Strings("topics", topics))
		}
	}
	s.logger.Info("ingest: service started",
		zap.String("nats_url", s.cfg.NATSUrl),
		zap.String("schema", s.cfg.SchemaPath),
	)
	return nil
}

// Stop gracefully stops the ingestion service and closes the NATS connection.
func (s *Service) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	if s.nc != nil {
		s.nc.Drain() //nolint:errcheck
	}
	s.logger.Info("ingest: service stopped")
}

// Ingest validates and processes a single raw event payload.
// Invalid events are routed to the dead letter queue.
func (s *Service) Ingest(ctx context.Context, rawPayload []byte) error {
	var event map[string]interface{}
	if err := json.Unmarshal(rawPayload, &event); err != nil {
		s.logger.Warn("ingest: invalid JSON payload", zap.Error(err))
		s.deadLetter(ctx, rawPayload, "invalid_json")
		return fmt.Errorf("ingest: unmarshal event: %w", err)
	}

	if err := s.validate(event); err != nil {
		s.logger.Warn("ingest: schema validation failed",
			zap.Error(err),
			zap.Any("event_id", event["event_id"]),
		)
		s.deadLetter(ctx, rawPayload, "schema_validation_failed")
		return fmt.Errorf("ingest: validate event: %w", err)
	}

	if err := s.handler.HandleEvent(ctx, event); err != nil {
		return fmt.Errorf("ingest: handle event: %w", err)
	}

	s.logger.Debug("ingest: event processed",
		zap.Any("event_id", event["event_id"]),
		zap.Any("domain", event["domain"]),
	)
	return nil
}

// validate performs schema-driven validation on the event.
// When the schema is loaded it uses the schema's required field list; otherwise
// it falls back to the hardcoded minimum required set.
// Type and enum constraints are always enforced for core fields.
func (s *Service) validate(event map[string]interface{}) error {
	// Derive required fields from the loaded schema or use the hardcoded baseline.
	required := []string{"event_id", "timestamp", "source", "domain", "severity", "risk_score", "tier", "actor", "target", "human_approved", "audit_hash"}
	if s.schema != nil {
		if schemaRequired, ok := s.schema["required"].([]interface{}); ok && len(schemaRequired) > 0 {
			required = make([]string, 0, len(schemaRequired))
			for _, f := range schemaRequired {
				if fs, ok := f.(string); ok {
					required = append(required, fs)
				}
			}
		}
	}
	for _, field := range required {
		if _, ok := event[field]; !ok {
			return fmt.Errorf("missing required field: %s", field)
		}
	}

	// Enum: domain
	domain, _ := event["domain"].(string)
	validDomains := map[string]bool{"host": true, "comms": true, "agent": true, "model": true}
	if !validDomains[domain] {
		return fmt.Errorf("invalid domain: %q (must be one of: host, comms, agent, model)", domain)
	}

	// Enum: severity
	if sev, ok := event["severity"].(string); ok {
		validSeverities := map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
		if !validSeverities[sev] {
			return fmt.Errorf("invalid severity: %q", sev)
		}
	}

	// Enum: tier
	if tier, ok := event["tier"].(string); ok {
		validTiers := map[string]bool{"T0": true, "T1": true, "T2": true, "T3": true, "T4": true}
		if !validTiers[tier] {
			return fmt.Errorf("invalid tier: %q (must be T0–T4)", tier)
		}
	}

	// Type: risk_score must be a number.
	switch event["risk_score"].(type) {
	case float64, int, int64:
		// valid
	default:
		return fmt.Errorf("risk_score must be a number, got %T", event["risk_score"])
	}

	return nil
}

// deadLetter routes an invalid payload to the dead letter topic.
// If a NATS connection is available the payload is published with a reason header;
// otherwise the error is logged for offline inspection.
func (s *Service) deadLetter(_ context.Context, payload []byte, reason string) {
	s.logger.Warn("ingest: dead letter",
		zap.String("reason", reason),
		zap.Int("payload_bytes", len(payload)),
	)
	if s.nc == nil || s.cfg.DeadLetterTopic == "" {
		return
	}
	msg := &nats.Msg{
		Subject: s.cfg.DeadLetterTopic,
		Data:    payload,
		Header:  nats.Header{"X-DLQ-Reason": []string{reason}},
	}
	if err := s.nc.PublishMsg(msg); err != nil {
		s.logger.Warn("ingest: dead letter publish failed",
			zap.String("topic", s.cfg.DeadLetterTopic),
			zap.Error(err),
		)
	}
}

// loadSchema reads the JSON schema file into memory.
func (s *Service) loadSchema() error {
	if s.cfg.SchemaPath == "" {
		s.logger.Warn("ingest: no schema path configured; validation will be basic")
		return nil
	}
	data, err := os.ReadFile(s.cfg.SchemaPath)
	if err != nil {
		s.logger.Warn("ingest: schema file not found; validation will be basic",
			zap.String("path", s.cfg.SchemaPath), zap.Error(err))
		return nil
	}
	if err := json.Unmarshal(data, &s.schema); err != nil {
		return fmt.Errorf("ingest: parse schema: %w", err)
	}
	s.logger.Info("ingest: schema loaded", zap.String("path", s.cfg.SchemaPath))
	return nil
}

// HandleEvent implements EventHandler so the ingest service itself can be used as a handler.
func (s *Service) HandleEvent(ctx context.Context, event map[string]interface{}) error {
	return s.handler.HandleEvent(ctx, event)
}
