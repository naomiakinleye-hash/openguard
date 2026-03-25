// Command networkguard-agent is the NetworkGuard sensor binary.
// It subscribes to HostGuard raw events on NATS, filters for network-related
// event types, enriches them with AI-powered threat classification via the
// model-gateway, and republishes as network-domain events.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/networkguard/common"
	networkguard "github.com/DiniMuhd7/openguard/adapters/networkguard"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic("networkguard-agent: failed to create logger: " + err.Error())
	}
	defer logger.Sync() //nolint:errcheck

	cfg := buildConfig(logger)

	sensor, err := networkguard.NewNetworkGuardSensor(cfg, logger)
	if err != nil {
		logger.Fatal("networkguard-agent: failed to create sensor", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sensor.Start(ctx); err != nil {
		logger.Fatal("networkguard-agent: failed to start sensor", zap.Error(err))
	}

	logger.Info("networkguard-agent: started",
		zap.String("nats_url", cfg.NATSUrl),
		zap.String("source_topic", cfg.SourceTopic),
		zap.String("publish_topic", cfg.PublishTopic),
		zap.Bool("ai_enabled", cfg.ModelGatewayEnabled),
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("networkguard-agent: shutting down")
	if err := sensor.Stop(); err != nil {
		logger.Warn("networkguard-agent: stop error", zap.Error(err))
	}
	logger.Info("networkguard-agent: stopped")
}

// buildConfig reads configuration from environment variables.
func buildConfig(logger *zap.Logger) common.Config {
	cfg := common.DefaultConfig()

	if v := os.Getenv("OPENGUARD_NATS_URL"); v != "" {
		cfg.NATSUrl = v
	}
	if v := os.Getenv("OPENGUARD_NETWORKGUARD_SOURCE_TOPIC"); v != "" {
		cfg.SourceTopic = v
	}
	if v := os.Getenv("OPENGUARD_NETWORKGUARD_PUBLISH_TOPIC"); v != "" {
		cfg.PublishTopic = v
	}

	// AI enrichment via model-gateway.
	if v := os.Getenv("OPENGUARD_NETWORKGUARD_MODEL_GATEWAY_ENABLED"); v == "true" {
		cfg.ModelGatewayEnabled = true
	}
	if v := os.Getenv("OPENGUARD_NETWORKGUARD_MODEL_GATEWAY_TOPIC"); v != "" {
		cfg.ModelGatewayTopic = v
	}
	if v := os.Getenv("OPENGUARD_NETWORKGUARD_MODEL_GATEWAY_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.ModelGatewayTimeout = d
		} else {
			logger.Warn("networkguard-agent: invalid OPENGUARD_NETWORKGUARD_MODEL_GATEWAY_TIMEOUT",
				zap.Error(err))
		}
	}
	if v := os.Getenv("OPENGUARD_NETWORKGUARD_MODEL_GATEWAY_AGENT_ID"); v != "" {
		cfg.ModelGatewayAgentID = v
	}

	return cfg
}
