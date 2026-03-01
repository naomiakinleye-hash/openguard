//go:build linux

// Package hostguard provides the cross-platform HostGuard sensor entry point.
package hostguard

import (
	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	linux "github.com/DiniMuhd7/openguard/adapters/hostguard/linux"
	"go.uber.org/zap"
)

// NewSensor returns the platform-appropriate Sensor implementation.
// On Linux, this returns a LinuxSensor.
func NewSensor(cfg common.Config, logger *zap.Logger) (common.Sensor, error) {
	publisher, err := common.NewPublisher(cfg.NATSUrl, cfg.RawEventTopic, logger)
	if err != nil {
		return nil, err
	}
	return linux.NewSensor(cfg, publisher, logger), nil
}
