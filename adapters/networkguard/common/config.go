// Package networkguardcommon provides shared configuration for the NetworkGuard sensor.
package networkguardcommon

import "time"

// networkEventTypes is the set of HostGuard event_type values that are
// classified as network-domain events by the NetworkGuard layer.
var NetworkEventTypes = map[string]bool{
	"connection_established":    true,
	"connection_closed":         true,
	"suspicious_connection":     true,
	"high_volume_connection":    true,
	"dns_query":                 true,
	"dns_config_changed":        true,
	"port_scan":                 true,
	"c2_beaconing":              true,
	"lateral_movement":          true,
	"dns_tunneling":             true,
	"protocol_anomaly":          true,
	"geo_ip_anomaly":            true,
	"network_data_exfiltration": true,
	"low_and_slow_anomaly":      true,
}

// Config holds the configuration for the NetworkGuard sensor.
type Config struct {
	// NATSUrl is the NATS server URL.
	NATSUrl string
	// SourceTopic is the NATS topic to subscribe to for raw host events.
	// Default: "openguard.hostguard.raw".
	SourceTopic string
	// PublishTopic is the NATS topic to publish enriched network events.
	// Default: "openguard.networkguard.raw".
	PublishTopic string

	// ModelGatewayEnabled enables AI threat enrichment via the model-gateway.
	ModelGatewayEnabled bool
	// ModelGatewayTopic is the NATS subject consumed by the model-gateway.
	// Default: "openguard.modelguard.requests".
	ModelGatewayTopic string
	// ModelGatewayTimeout is the per-request deadline for AI enrichment calls.
	// Default: 10s.
	ModelGatewayTimeout time.Duration
	// ModelGatewayAgentID identifies NetworkGuard to the model-gateway rate-limiter.
	// Default: "networkguard".
	ModelGatewayAgentID string
}

// DefaultConfig returns a Config with sensible defaults applied.
func DefaultConfig() Config {
	return Config{
		NATSUrl:             "nats://localhost:4222",
		SourceTopic:         "openguard.hostguard.raw",
		PublishTopic:        "openguard.networkguard.raw",
		ModelGatewayTopic:   "openguard.modelguard.requests",
		ModelGatewayTimeout: 10 * time.Second,
		ModelGatewayAgentID: "networkguard",
	}
}
