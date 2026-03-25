//go:build linux

// Package hostguard provides the cross-platform HostGuard sensor entry point.
package hostguard

import (
	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	linux "github.com/DiniMuhd7/openguard/adapters/hostguard/linux"
	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// NewSensor returns the platform-appropriate Sensor implementation.
// On Linux, this returns a LinuxSensor with optional AI enrichment.
func NewSensor(cfg common.Config, logger *zap.Logger) (common.Sensor, error) {
	publisher, err := common.NewPublisher(cfg.NATSUrl, cfg.RawEventTopic, logger)
	if err != nil {
		return nil, err
	}
	if cfg.ModelGatewayEnabled {
		nc, ncErr := nats.Connect(cfg.NATSUrl,
			nats.Name("openguard-hostguard-ai"),
			nats.MaxReconnects(-1),
		)
		if ncErr != nil {
			logger.Warn("hostguard: AI enrichment NATS connect failed — running without AI",
				zap.Error(ncErr))
		} else {
			mc := common.NewHostModelIntelClient(nc, cfg.ModelGatewayTopic, cfg.ModelGatewayTimeout, cfg.ModelGatewayAgentID, logger)
			publisher.WithModelIntelClient(mc)
			logger.Info("hostguard: AI enrichment enabled",
				zap.String("topic", cfg.ModelGatewayTopic),
				zap.String("agent_id", cfg.ModelGatewayAgentID),
			)
		}
	}
	return linux.NewSensor(cfg, publisher, logger), nil
}

// NewSensorDirect constructs a LinuxSensor that bypasses NATS and delivers events
// directly to the provided handler function. This enables in-process operation
// without a running NATS server.
func NewSensorDirect(cfg common.Config, handler func([]byte) error, logger *zap.Logger) (common.Sensor, error) {
	publisher := common.NewDirectPublisher(handler, cfg.RawEventTopic, logger)
	return linux.NewSensor(cfg, publisher, logger), nil
}
