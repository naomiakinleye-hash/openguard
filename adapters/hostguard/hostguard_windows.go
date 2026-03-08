//go:build windows

// Package hostguard provides the cross-platform HostGuard sensor entry point.
package hostguard

import (
	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	windows "github.com/DiniMuhd7/openguard/adapters/hostguard/windows"
	"go.uber.org/zap"
)

// NewSensor returns the platform-appropriate Sensor implementation.
// On Windows, this returns a WindowsSensor.
func NewSensor(cfg common.Config, logger *zap.Logger) (common.Sensor, error) {
	publisher, err := common.NewPublisher(cfg.NATSUrl, cfg.RawEventTopic, logger)
	if err != nil {
		return nil, err
	}
	return windows.NewSensor(cfg, publisher, logger), nil
}

// NewSensorDirect constructs a WindowsSensor that bypasses NATS and delivers events
// directly to the provided handler function. This enables in-process operation
// without a running NATS server.
func NewSensorDirect(cfg common.Config, handler func([]byte) error, logger *zap.Logger) (common.Sensor, error) {
	publisher := common.NewDirectPublisher(handler, cfg.RawEventTopic, logger)
	return windows.NewSensor(cfg, publisher, logger), nil
}
