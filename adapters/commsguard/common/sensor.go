// Package commsguardcommon provides shared types and utilities for the CommsGuard sensor.
package commsguardcommon

import (
	"context"
	"time"
)

// Sensor is the interface all channel-specific CommsGuard adapters must implement.
type Sensor interface {
	// Start begins the sensor (webhook listener or polling loop) and returns immediately.
	Start(ctx context.Context) error
	// Stop gracefully shuts down the sensor.
	Stop() error
	// Channel returns the communication channel identifier (e.g. "whatsapp", "telegram").
	Channel() string
	// HealthCheck returns nil if the sensor is running correctly.
	HealthCheck(ctx context.Context) error
}

// Config holds the configuration for the CommsGuard sensor.
type Config struct {
	// NATSUrl is the NATS server URL.
	NATSUrl string
	// RawEventTopic is the NATS topic for raw comms events.
	// Default: "openguard.commsguard.raw"
	RawEventTopic string
	// ListenAddr is the HTTP webhook listen address.
	// Default: ":8090"
	ListenAddr string

	// Per-channel credentials (empty = channel disabled).
	WhatsAppAppSecret    string
	WhatsAppVerifyToken  string
	TelegramBotToken     string
	TelegramWebhookSecret string // optional: validated against X-Telegram-Bot-Api-Secret-Token header
	MessengerAppSecret   string
	MessengerVerifyToken string
	TwilioAuthToken      string
	TwilioAccountSID     string
	TwitterBearerToken   string
	TwitterWebhookSecret string

	// Threat analysis config.
	BulkMessageThreshold  int           // default: 20
	BulkMessageWindow     time.Duration // default: 60s
	EnableContentAnalysis bool          // default: true (set false for privacy-first mode)

	// Model-gateway AI enrichment config.
	// When ModelGatewayEnabled is true the ThreatAnalyzer will forward each
	// message to the model-gateway agent (via NATS request-reply) after
	// completing its heuristic pass, and merge any additional indicators
	// returned by the model into the event's indicator list.
	ModelGatewayEnabled bool          // default: false (opt-in)
	ModelGatewayTopic   string        // default: "openguard.modelguard.requests"
	ModelGatewayTimeout time.Duration // default: 10s — per-request deadline
	ModelGatewayAgentID string        // default: "commsguard"

	// CrossChannelWindow is the look-back period used by the cross-channel
	// correlation tracker to detect the same threat appearing across multiple
	// communication channels.  Default: 24 h.
	CrossChannelWindow time.Duration

	// Tunnel config — set TunnelMode to "ngrok" or "cloudflared" to automatically
	// expose the local webhook server to the internet without manual port-forwarding.
	// Leave empty (default) to run without a tunnel (LAN / localhost only).
	//
	//   ngrok       — requires ngrok CLI on PATH; authenticate once with
	//                 `ngrok config add-authtoken <token>` or pass NgrokAuthToken.
	//                 Free accounts: https://dashboard.ngrok.com/signup
	//
	//   cloudflared — requires cloudflared CLI on PATH; no account needed for
	//                 quick tunnels (*.trycloudflare.com).
	//                 Download: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/
	TunnelMode     string // "ngrok" | "cloudflared" | "" (disabled)
	NgrokAuthToken string // optional ngrok auth token (overrides `ngrok config add-authtoken`)
}

// DefaultConfig returns a Config with sensible defaults applied.
func DefaultConfig() Config {
	return Config{
		NATSUrl:               "nats://localhost:4222",
		RawEventTopic:         "openguard.commsguard.raw",
		ListenAddr:            ":8090",
		BulkMessageThreshold:  20,
		BulkMessageWindow:     60 * time.Second,
		EnableContentAnalysis: true,
		ModelGatewayTopic:     "openguard.modelguard.requests",
		ModelGatewayTimeout:   10 * time.Second,
		ModelGatewayAgentID:   "commsguard",
		CrossChannelWindow:    24 * time.Hour,
	}
}
