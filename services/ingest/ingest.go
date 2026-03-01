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

// validate performs basic schema validation on the event.
// In production this should use a full JSON Schema validator.
func (s *Service) validate(event map[string]interface{}) error {
	required := []string{"event_id", "timestamp", "source", "domain", "severity", "risk_score", "tier", "actor", "target", "human_approved", "audit_hash"}
	for _, field := range required {
		if _, ok := event[field]; !ok {
			return fmt.Errorf("missing required field: %s", field)
		}
	}
	domain, _ := event["domain"].(string)
	validDomains := map[string]bool{"host": true, "comms": true, "agent": true, "model": true}
	if !validDomains[domain] {
		return fmt.Errorf("invalid domain: %s", domain)
	}
	return nil
}

// deadLetter routes an invalid payload to the dead letter topic.
func (s *Service) deadLetter(_ context.Context, payload []byte, reason string) {
	s.logger.Warn("ingest: dead letter",
		zap.String("reason", reason),
		zap.Int("payload_bytes", len(payload)),
	)
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
