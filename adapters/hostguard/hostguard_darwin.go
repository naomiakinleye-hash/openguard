//go:build darwin

// Package hostguard provides the cross-platform HostGuard sensor entry point.
package hostguard

import (
	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	darwin "github.com/DiniMuhd7/openguard/adapters/hostguard/darwin"
	"go.uber.org/zap"
)

// NewSensor returns the platform-appropriate Sensor implementation.
// On macOS, this returns a DarwinSensor.
func NewSensor(cfg common.Config, logger *zap.Logger) (common.Sensor, error) {
	publisher, err := common.NewPublisher(cfg.NATSUrl, cfg.RawEventTopic, logger)
	if err != nil {
		return nil, err
	}
	return darwin.NewSensor(cfg, publisher, logger), nil
}
