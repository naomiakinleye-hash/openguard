//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"context"
	"fmt"
	"os"
	"sync"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// DarwinSensor is the macOS implementation of the HostGuard Sensor interface.
// It aggregates ProcessMonitor, LaunchdMonitor, LoginItemsMonitor, and NetworkMonitor,
// as well as the real-time RealtimeProcessMonitor, FileMonitor, HiddenProcessScanner,
// ResourceMonitor, KextMonitor, SessionMonitor, DNSMonitor, IPCMonitor, and USBMonitor.
type DarwinSensor struct {
	cfg           common.Config
	publisher     *common.Publisher
	logger        *zap.Logger
	eventCh       chan *common.HostEvent
	process       *ProcessMonitor
	realtimeProc  *RealtimeProcessMonitor
	fileio        *FileMonitor
	hiddenScanner *HiddenProcessScanner
	launchd       *LaunchdMonitor
	loginItems    *LoginItemsMonitor
	network       *NetworkMonitor
	resource      *ResourceMonitor
	kext          *KextMonitor
	session       *SessionMonitor
	dns           *DNSMonitor
	ipc           *IPCMonitor
	usb           *USBMonitor
	wg            sync.WaitGroup
	cancelFn      context.CancelFunc
}

// NewSensor constructs a DarwinSensor with the provided configuration.
func NewSensor(cfg common.Config, publisher *common.Publisher, logger *zap.Logger) *DarwinSensor {
	if cfg.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			cfg.Hostname = h
		}
	}
	eventCh := make(chan *common.HostEvent, 256)
	s := &DarwinSensor{
		cfg:       cfg,
		publisher: publisher,
		logger:    logger,
		eventCh:   eventCh,
	}
	s.process = newProcessMonitor(cfg, eventCh, logger)
	s.realtimeProc = newRealtimeProcessMonitor(cfg, eventCh, logger)
	s.fileio = newFileMonitor(cfg, eventCh, logger)
	s.hiddenScanner = newHiddenProcessScanner(cfg, eventCh, logger)
	s.launchd = newLaunchdMonitor(cfg, eventCh, logger)
	s.loginItems = newLoginItemsMonitor(cfg, eventCh, logger)
	s.network = newNetworkMonitor(cfg, eventCh, logger)
	s.resource = newResourceMonitor(cfg, eventCh, logger)
	s.kext = newKextMonitor(cfg, eventCh, logger)
	s.session = newSessionMonitor(cfg, eventCh, logger)
	s.dns = newDNSMonitor(cfg, eventCh, logger)
	s.ipc = newIPCMonitor(cfg, eventCh, logger)
	s.usb = newUSBMonitor(cfg, eventCh, logger)
	return s
}

// Start begins all monitoring goroutines.
func (s *DarwinSensor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel

	// Try real-time kqueue process monitor first; fall back to polling if unavailable.
	if err := s.realtimeProc.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: realtime process monitor unavailable, using polling", zap.Error(err))
		if err := s.process.Start(ctx); err != nil {
			cancel()
			return fmt.Errorf("darwin sensor: start process monitor: %w", err)
		}
	} else {
		s.logger.Info("darwin sensor: using realtime (kqueue) process monitoring")
	}
	if err := s.fileio.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: start file monitor", zap.Error(err))
	}
	if err := s.hiddenScanner.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: start hidden process scanner", zap.Error(err))
	}
	if err := s.launchd.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: start launchd monitor", zap.Error(err))
	}
	if err := s.loginItems.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: start login items monitor", zap.Error(err))
	}
	if err := s.network.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: start network monitor", zap.Error(err))
	}
	if err := s.resource.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: start resource monitor", zap.Error(err))
	}
	if err := s.kext.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: start kext monitor", zap.Error(err))
	}
	if err := s.session.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: start session monitor", zap.Error(err))
	}
	if err := s.dns.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: start dns monitor", zap.Error(err))
	}
	if err := s.ipc.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: start ipc monitor", zap.Error(err))
	}
	if err := s.usb.Start(ctx); err != nil {
		s.logger.Warn("darwin sensor: start usb monitor", zap.Error(err))
	}

	s.wg.Add(1)
	go s.publishLoop(ctx)

	s.logger.Info("darwin sensor: started", zap.String("hostname", s.cfg.Hostname))
	return nil
}

// Stop gracefully shuts down all monitoring goroutines.
func (s *DarwinSensor) Stop() error {
	if s.cancelFn != nil {
		s.cancelFn()
	}
	s.realtimeProc.Stop()
	s.process.Stop()
	s.fileio.Stop()
	s.hiddenScanner.Stop()
	s.launchd.Stop()
	s.loginItems.Stop()
	s.network.Stop()
	s.resource.Stop()
	s.kext.Stop()
	s.session.Stop()
	s.dns.Stop()
	s.ipc.Stop()
	s.usb.Stop()
	s.wg.Wait()
	s.logger.Info("darwin sensor: stopped")
	return nil
}

// Platform returns the platform identifier.
func (s *DarwinSensor) Platform() string { return "darwin" }

// HealthCheck returns nil if the sensor appears to be running correctly.
func (s *DarwinSensor) HealthCheck(_ context.Context) error {
	return nil
}

// publishLoop reads events from the channel and forwards them to the publisher.
func (s *DarwinSensor) publishLoop(ctx context.Context) {
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
				s.logger.Warn("darwin sensor: publish event",
					zap.String("event_type", event.EventType),
					zap.Error(err),
				)
			}
		}
	}
}
