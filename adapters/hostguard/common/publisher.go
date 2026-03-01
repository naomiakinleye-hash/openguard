// Package hostguardcommon provides shared types and utilities for the HostGuard sensor.
package hostguardcommon

import (
	"context"
	"fmt"

	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// Publisher publishes HostEvents to NATS as UnifiedEvent JSON payloads.
type Publisher struct {
	nc     *nats.Conn
	topic  string
	logger *zap.Logger
}

// NewPublisher creates a new Publisher connected to the given NATS URL
// and publishing to the given topic.
func NewPublisher(natsURL, topic string, logger *zap.Logger) (*Publisher, error) {
	nc, err := nats.Connect(natsURL,
		nats.Name("openguard-hostguard"),
		nats.MaxReconnects(-1),
	)
	if err != nil {
		return nil, fmt.Errorf("hostguard: connect to NATS at %s: %w", natsURL, err)
	}
	return &Publisher{nc: nc, topic: topic, logger: logger}, nil
}

// Publish converts the HostEvent to a UnifiedEvent JSON payload and publishes it to NATS.
func (p *Publisher) Publish(_ context.Context, event *HostEvent) error {
	payload, err := event.ToUnifiedEvent()
	if err != nil {
		return fmt.Errorf("hostguard: to unified event: %w", err)
	}
	if err := p.nc.Publish(p.topic, payload); err != nil {
		return fmt.Errorf("hostguard: NATS publish to %s: %w", p.topic, err)
	}
	p.logger.Debug("hostguard: published event",
		zap.String("topic", p.topic),
		zap.String("event_type", event.EventType),
		zap.String("platform", event.Platform),
	)
	return nil
}

// Close drains and closes the underlying NATS connection.
func (p *Publisher) Close() {
	if p.nc != nil {
		p.nc.Drain() //nolint:errcheck
	}
}
