//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"context"
	"sync"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// CloudMetadataMonitor is a no-op stub for macOS. Cloud IMDS monitoring is
// primarily relevant on Linux where /proc/net/tcp is available.
type CloudMetadataMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newCloudMetadataMonitor creates a CloudMetadataMonitor stub for macOS.
func newCloudMetadataMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *CloudMetadataMonitor {
	return &CloudMetadataMonitor{cfg: cfg, eventCh: eventCh, logger: logger}
}

// Start is a no-op on macOS.
func (m *CloudMetadataMonitor) Start(_ context.Context) error {
	m.logger.Debug("darwin: cloud metadata monitor: no-op on macOS")
	return nil
}

// Stop is a no-op on macOS.
func (m *CloudMetadataMonitor) Stop() {}
