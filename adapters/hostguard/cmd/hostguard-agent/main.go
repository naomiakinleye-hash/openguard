//go:build windows || darwin || linux

// main.go — HostGuard Agent
// A lightweight sensor binary that runs on the monitored host and ships
// security events to the OpenGuard ingest service via NATS.
package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	hostguard "github.com/DiniMuhd7/openguard/adapters/hostguard"
	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic("hostguard-agent: failed to init logger: " + err.Error())
	}
	defer logger.Sync() //nolint:errcheck

	cfg := buildConfig(logger)

	sensor, err := hostguard.NewSensor(cfg, logger)
	if err != nil {
		logger.Fatal("hostguard-agent: failed to create sensor", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sensor.Start(ctx); err != nil {
		logger.Fatal("hostguard-agent: failed to start sensor", zap.Error(err))
	}
	logger.Info("hostguard-agent: sensor started",
		zap.String("platform", sensor.Platform()),
		zap.String("nats_url", cfg.NATSUrl),
		zap.String("topic", cfg.RawEventTopic),
	)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("hostguard-agent: shutting down")
	if err := sensor.Stop(); err != nil {
		logger.Warn("hostguard-agent: stop sensor", zap.Error(err))
	}
	logger.Info("hostguard-agent: stopped")
}

// buildConfig reads configuration from environment variables with defaults.
func buildConfig(logger *zap.Logger) common.Config {
	cfg := common.DefaultConfig()

	if v := os.Getenv("OPENGUARD_NATS_URL"); v != "" {
		cfg.NATSUrl = v
	} else {
		cfg.NATSUrl = "nats://localhost:4222"
	}

	if v := os.Getenv("OPENGUARD_HOSTGUARD_TOPIC"); v != "" {
		cfg.RawEventTopic = v
	} else {
		cfg.RawEventTopic = "openguard.hostguard.raw"
	}

	if v := os.Getenv("OPENGUARD_HOSTGUARD_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.PollInterval = d
		} else {
			logger.Warn("hostguard-agent: invalid OPENGUARD_HOSTGUARD_POLL_INTERVAL", zap.Error(err))
		}
	}

	if v := os.Getenv("OPENGUARD_HOSTGUARD_CPU_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.AnomalyThresholds.CPUPercentHigh = f
		}
	}

	if v := os.Getenv("OPENGUARD_HOSTGUARD_MEM_THRESHOLD_MB"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.AnomalyThresholds.MemoryMBHigh = f
		}
	}

	if v := os.Getenv("OPENGUARD_HOSTGUARD_SUSPICIOUS_PATHS"); v != "" {
		cfg.SuspiciousPaths = splitComma(v)
	}

	if v := os.Getenv("OPENGUARD_HOSTGUARD_ALLOWLIST"); v != "" {
		cfg.AllowlistedBinaries = splitComma(v)
	}

	// AI enrichment via model-gateway.
	if v := os.Getenv("OPENGUARD_HOSTGUARD_MODEL_GATEWAY_ENABLED"); v == "true" {
		cfg.ModelGatewayEnabled = true
	}
	cfg.ModelGatewayTopic = "openguard.modelguard.requests"
	if v := os.Getenv("OPENGUARD_HOSTGUARD_MODEL_GATEWAY_TOPIC"); v != "" {
		cfg.ModelGatewayTopic = v
	}
	cfg.ModelGatewayTimeout = 10 * time.Second
	if v := os.Getenv("OPENGUARD_HOSTGUARD_MODEL_GATEWAY_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.ModelGatewayTimeout = d
		} else {
			logger.Warn("hostguard-agent: invalid OPENGUARD_HOSTGUARD_MODEL_GATEWAY_TIMEOUT", zap.Error(err))
		}
	}
	cfg.ModelGatewayAgentID = "hostguard"
	if v := os.Getenv("OPENGUARD_HOSTGUARD_MODEL_GATEWAY_AGENT_ID"); v != "" {
		cfg.ModelGatewayAgentID = v
	}

	return cfg
}

// splitComma splits a comma-separated string and trims whitespace.
func splitComma(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
