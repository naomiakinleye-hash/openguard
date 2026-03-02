// Package commsguardcommon provides shared types and utilities for the CommsGuard sensor.
package commsguardcommon

import (
	"context"
	"fmt"

	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// Publisher publishes CommsEvents to NATS as UnifiedEvent JSON payloads.
type Publisher struct {
	nc                   *nats.Conn
	topic                string
	logger               *zap.Logger
	enableContentAnalysis bool
}

// NewPublisher creates a new Publisher connected to the given NATS URL
// and publishing to the given topic.
func NewPublisher(natsURL, topic string, enableContentAnalysis bool, logger *zap.Logger) (*Publisher, error) {
	nc, err := nats.Connect(natsURL,
		nats.Name("openguard-commsguard"),
		nats.MaxReconnects(-1),
	)
	if err != nil {
		return nil, fmt.Errorf("commsguard: connect to NATS at %s: %w", natsURL, err)
	}
	return &Publisher{nc: nc, topic: topic, enableContentAnalysis: enableContentAnalysis, logger: logger}, nil
}

// Publish converts the CommsEvent to a UnifiedEvent JSON payload and publishes it to NATS.
func (p *Publisher) Publish(_ context.Context, event *CommsEvent) error {
	var (
		payload []byte
		err     error
	)
	if p.enableContentAnalysis {
		payload, err = event.ToUnifiedEvent()
	} else {
		payload, err = event.ToUnifiedEventPrivacyFirst()
	}
	if err != nil {
		return fmt.Errorf("commsguard: to unified event: %w", err)
	}
	if err := p.nc.Publish(p.topic, payload); err != nil {
		return fmt.Errorf("commsguard: NATS publish to %s: %w", p.topic, err)
	}
	p.logger.Debug("commsguard: published event",
		zap.String("topic", p.topic),
		zap.String("event_type", event.EventType),
		zap.String("channel", event.Channel),
	)
	return nil
}

// Close drains and closes the underlying NATS connection.
func (p *Publisher) Close() {
	if p.nc != nil {
		p.nc.Drain() //nolint:errcheck
	}
}
