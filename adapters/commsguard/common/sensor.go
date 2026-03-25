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
	EnableContentAnalysis bool // default: true (set false for privacy-first mode)

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

	// Intercept and notify config.
	//
	// NotifyEnabled controls whether a warning is sent to the recipient via
	// the same channel whenever a threat is detected. Default: true.
	NotifyEnabled bool
	// InterceptEnabled controls whether CommsGuard attempts to suppress or
	// revoke the malicious message before the recipient reads it. Default: true.
	// Intercept is always best-effort — when the channel does not support
	// deletion (ErrInterceptUnsupported) the warning is still delivered.
	InterceptEnabled bool
	// ResponseTopic is the NATS subject the sensor subscribes to for
	// orchestrator-driven response events (see ResponseEvent). When the
	// response-orchestrator approves an action it publishes a ResponseEvent
	// here and the sensor dispatches the matching Notifier.
	// Default: "openguard.commsguard.response".
	ResponseTopic string

	// WhatsApp Business API notifier credentials.
	// Required when using the WBA path for outbound warning messages.
	// Leave empty to rely solely on the linked-device session (whatsmeow).
	WhatsAppAccessToken   string // WBA long-lived access token
	WhatsAppPhoneNumberID string // WBA phone number ID used to send messages

	// Twilio notifier credentials.
	// TwilioFromNumber is the E.164-formatted Twilio phone number used to
	// send outbound warning SMS messages (e.g. "+14155551234").
	// TwilioAuthToken and TwilioAccountSID are reused from the adapter fields above.
	TwilioFromNumber string

	// Messenger notifier credentials.
	// MessengerPageAccessToken is the Facebook Page access token with the
	// pages_messaging permission, used to send warning messages via the
	// Messenger Send API.  MessengerAppSecret/MessengerVerifyToken are reused
	// from the adapter fields above.
	MessengerPageAccessToken string
}

// DefaultConfig returns a Config with sensible defaults applied.
func DefaultConfig() Config {
	return Config{
		NATSUrl:               "nats://localhost:4222",
		RawEventTopic:         "openguard.commsguard.raw",
		ListenAddr:            ":8090",
		EnableContentAnalysis: true,
		ModelGatewayTopic:     "openguard.modelguard.requests",
		ModelGatewayTimeout:   10 * time.Second,
		ModelGatewayAgentID:   "commsguard",
		CrossChannelWindow:    24 * time.Hour,
		NotifyEnabled:         true,
		InterceptEnabled:      true,
		ResponseTopic:         "openguard.commsguard.response",
	}
}
