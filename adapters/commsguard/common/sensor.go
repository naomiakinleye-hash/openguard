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
	}
}
