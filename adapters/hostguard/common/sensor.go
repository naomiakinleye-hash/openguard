// Package hostguardcommon provides shared types and utilities for the HostGuard sensor.
package hostguardcommon

import (
	"context"
	"time"
)

// Sensor is the interface all platform-specific HostGuard sensors must implement.
type Sensor interface {
	// Start begins all monitoring goroutines and returns immediately.
	Start(ctx context.Context) error
	// Stop gracefully shuts down all monitoring goroutines.
	Stop() error
	// Platform returns the platform identifier ("windows", "darwin", "linux").
	Platform() string
	// HealthCheck returns nil if the sensor is running correctly.
	HealthCheck(ctx context.Context) error
}

// Config holds the configuration for a HostGuard sensor instance.
type Config struct {
	// Hostname is auto-detected if empty.
	Hostname string
	// NATSUrl is the NATS server URL.
	NATSUrl string
	// RawEventTopic is the NATS topic for raw host events.
	// Default: "openguard.hostguard.raw"
	RawEventTopic string
	// PollInterval is the polling interval for process monitoring.
	// Default: 5s.
	PollInterval time.Duration
	// AnomalyThresholds holds thresholds for anomaly detection.
	AnomalyThresholds AnomalyThresholds
	// SuspiciousPaths is the list of path prefixes considered suspicious (e.g. %TEMP%, /tmp, /dev/shm).
	SuspiciousPaths []string
	// AllowlistedBinaries is the list of known-good binary names to suppress from alerts.
	AllowlistedBinaries []string
	// SensitivePathPrefixes is the list of path prefixes considered sensitive for file I/O monitoring.
	SensitivePathPrefixes []string
	// HiddenScanInterval is the interval between hidden process scans. Default: 60s.
	HiddenScanInterval time.Duration
	// AllowedDNSResolvers is the list of DNS resolver IPs considered legitimate.
	// Default: well-known public resolvers.
	AllowedDNSResolvers []string
	// DisableRealtimeMonitor forces the polling-based ProcessMonitor even when the
	// realtime netlink process-connector is available.  Intended for testing in
	// container environments where the netlink monitor starts without error but
	// delivers events non-deterministically.
	DisableRealtimeMonitor bool

	// ModelGatewayEnabled enables AI threat enrichment via the model-gateway agent.
	ModelGatewayEnabled bool
	// ModelGatewayTopic is the NATS subject consumed by the model-gateway.
	// Default: "openguard.modelguard.requests".
	ModelGatewayTopic string
	// ModelGatewayTimeout is the per-request deadline for AI enrichment calls.
	// Default: 10s.
	ModelGatewayTimeout time.Duration
	// ModelGatewayAgentID identifies HostGuard to the model-gateway rate-limiter.
	// Default: "hostguard".
	ModelGatewayAgentID string
}

// AnomalyThresholds defines thresholds used for anomaly detection.
type AnomalyThresholds struct {
	// CPUPercentHigh is the CPU usage percentage above which a process is flagged. Default: 90.0.
	CPUPercentHigh float64
	// MemoryMBHigh is the RSS memory in MB above which a process is flagged. Default: 2048.0.
	MemoryMBHigh float64
	// NewProcessBurst is the number of new processes in one PollInterval that triggers a burst alert. Default: 20.
	NewProcessBurst int
}

// DefaultConfig returns a Config with sensible defaults applied.
func DefaultConfig() Config {
	return Config{
		RawEventTopic: "openguard.hostguard.raw",
		PollInterval:  5 * time.Second,
		AnomalyThresholds: AnomalyThresholds{
			CPUPercentHigh:  90.0,
			MemoryMBHigh:    2048.0,
			NewProcessBurst: 20,
		},
		SensitivePathPrefixes: []string{
			"/etc/passwd",
			"/etc/shadow",
			"/etc/sudoers",
			"/root",
			"/root/.ssh",
			"/boot",
			`C:\Windows\System32\drivers`,
			`C:\Windows\System32`,
		},
		HiddenScanInterval: 60 * time.Second,
		AllowedDNSResolvers: []string{
			"8.8.8.8", "1.1.1.1", "8.8.4.4", "9.9.9.9", "208.67.222.222",
		},
	}
}
