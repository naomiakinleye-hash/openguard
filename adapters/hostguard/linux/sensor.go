//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"context"
	"fmt"
	"os"
	"sync"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// LinuxSensor is the Linux implementation of the HostGuard Sensor interface.
// It aggregates ProcessMonitor, SystemdMonitor, CronMonitor, and NetworkMonitor,
// as well as the real-time RealtimeProcessMonitor, FileMonitor, and HiddenProcessScanner.
type LinuxSensor struct {
	cfg           common.Config
	publisher     *common.Publisher
	logger        *zap.Logger
	eventCh       chan *common.HostEvent
	process       *ProcessMonitor
	realtimeProc  *RealtimeProcessMonitor
	fileio        *FileMonitor
	hiddenScanner *HiddenProcessScanner
	systemd       *SystemdMonitor
	cron          *CronMonitor
	network       *NetworkMonitor
	wg            sync.WaitGroup
	cancelFn      context.CancelFunc
}

// NewSensor constructs a LinuxSensor with the provided configuration.
func NewSensor(cfg common.Config, publisher *common.Publisher, logger *zap.Logger) *LinuxSensor {
	if cfg.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			cfg.Hostname = h
		}
	}
	eventCh := make(chan *common.HostEvent, 256)
	s := &LinuxSensor{
		cfg:       cfg,
		publisher: publisher,
		logger:    logger,
		eventCh:   eventCh,
	}
	s.process = newProcessMonitor(cfg, eventCh, logger)
	s.realtimeProc = newRealtimeProcessMonitor(cfg, eventCh, logger)
	s.fileio = newFileMonitor(cfg, eventCh, logger)
	s.hiddenScanner = newHiddenProcessScanner(cfg, eventCh, logger)
	s.systemd = newSystemdMonitor(cfg, eventCh, logger)
	s.cron = newCronMonitor(cfg, eventCh, logger)
	s.network = newNetworkMonitor(cfg, eventCh, logger)
	return s
}

// Start begins all monitoring goroutines.
func (s *LinuxSensor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel

	// Try real-time netlink process monitor first; fall back to polling if unavailable.
	if err := s.realtimeProc.Start(ctx); err != nil {
		s.logger.Warn("linux sensor: realtime process monitor unavailable, using polling", zap.Error(err))
		if err := s.process.Start(ctx); err != nil {
			cancel()
			return fmt.Errorf("linux sensor: start process monitor: %w", err)
		}
	} else {
		s.logger.Info("linux sensor: using realtime (netlink) process monitoring")
	}
	if err := s.fileio.Start(ctx); err != nil {
		s.logger.Warn("linux sensor: start file monitor", zap.Error(err))
	}
	if err := s.hiddenScanner.Start(ctx); err != nil {
		s.logger.Warn("linux sensor: start hidden process scanner", zap.Error(err))
	}
	if err := s.systemd.Start(ctx); err != nil {
		s.logger.Warn("linux sensor: start systemd monitor", zap.Error(err))
	}
	if err := s.cron.Start(ctx); err != nil {
		s.logger.Warn("linux sensor: start cron monitor", zap.Error(err))
	}
	if err := s.network.Start(ctx); err != nil {
		s.logger.Warn("linux sensor: start network monitor", zap.Error(err))
	}

	s.wg.Add(1)
	go s.publishLoop(ctx)

	s.logger.Info("linux sensor: started", zap.String("hostname", s.cfg.Hostname))
	return nil
}

// Stop gracefully shuts down all monitoring goroutines.
func (s *LinuxSensor) Stop() error {
	if s.cancelFn != nil {
		s.cancelFn()
	}
	s.realtimeProc.Stop()
	s.process.Stop()
	s.fileio.Stop()
	s.hiddenScanner.Stop()
	s.systemd.Stop()
	s.cron.Stop()
	s.network.Stop()
	s.wg.Wait()
	s.logger.Info("linux sensor: stopped")
	return nil
}

// Platform returns the platform identifier.
func (s *LinuxSensor) Platform() string { return "linux" }

// HealthCheck returns nil if the sensor appears to be running.
func (s *LinuxSensor) HealthCheck(_ context.Context) error {
	if _, err := os.ReadDir("/proc"); err != nil {
		return fmt.Errorf("linux sensor: /proc not accessible: %w", err)
	}
	return nil
}

// publishLoop reads events from the channel and forwards them to the publisher.
func (s *LinuxSensor) publishLoop(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-s.eventCh:
			if !ok {
				return
			}
			if err := s.publisher.Publish(ctx, event); err != nil {
				s.logger.Warn("linux sensor: publish event",
					zap.String("event_type", event.EventType),
					zap.Error(err),
				)
			}
		}
	}
}
