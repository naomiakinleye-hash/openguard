// Package agentguardcommon provides shared types and utilities for the AgentGuard sensor.
package agentguardcommon

import "time"

// Config holds the configuration for the AgentGuard sensor.
type Config struct {
	// NATSUrl is the NATS server URL.
	NATSUrl string
	// RawEventTopic is the NATS topic for raw agent events.
	// Default: "openguard.agentguard.raw"
	RawEventTopic string
	// ListenAddr is the HTTP intercept listen address.
	// Default: ":8095"
	ListenAddr string

	// ModelGatewayEnabled enables AI threat enrichment via the model-gateway agent.
	ModelGatewayEnabled bool
	// ModelGatewayTopic is the NATS subject consumed by the model-gateway.
	// Default: "openguard.modelguard.requests".
	ModelGatewayTopic string
	// ModelGatewayTimeout is the per-request deadline for AI enrichment calls.
	// Default: 10s.
	ModelGatewayTimeout time.Duration
	// ModelGatewayAgentID identifies AgentGuard to the model-gateway rate-limiter.
	// Default: "agentguard".
	ModelGatewayAgentID string
}

// DefaultConfig returns a Config with sensible defaults applied.
func DefaultConfig() Config {
	return Config{
		NATSUrl:             "nats://localhost:4222",
		RawEventTopic:       "openguard.agentguard.raw",
		ListenAddr:          ":8095",
		ModelGatewayTopic:   "openguard.modelguard.requests",
		ModelGatewayTimeout: 10 * time.Second,
		ModelGatewayAgentID: "agentguard",
	}
}
