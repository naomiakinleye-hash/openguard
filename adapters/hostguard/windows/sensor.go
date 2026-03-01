//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"context"
	"fmt"
	"os"
	"sync"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// WindowsSensor is the Windows implementation of the HostGuard Sensor interface.
// It aggregates ProcessMonitor, SchedulerMonitor, and RegistryMonitor.
type WindowsSensor struct {
	cfg       common.Config
	publisher *common.Publisher
	logger    *zap.Logger
	eventCh   chan *common.HostEvent
	process   *ProcessMonitor
	scheduler *SchedulerMonitor
	registry  *RegistryMonitor
	wg        sync.WaitGroup
	cancelFn  context.CancelFunc
}

// NewSensor constructs a WindowsSensor with the provided configuration.
func NewSensor(cfg common.Config, publisher *common.Publisher, logger *zap.Logger) *WindowsSensor {
	if cfg.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			cfg.Hostname = h
		}
	}
	eventCh := make(chan *common.HostEvent, 256)
	s := &WindowsSensor{
		cfg:       cfg,
		publisher: publisher,
		logger:    logger,
		eventCh:   eventCh,
	}
	s.process = newProcessMonitor(cfg, eventCh, logger)
	s.scheduler = newSchedulerMonitor(cfg, eventCh, logger)
	s.registry = newRegistryMonitor(cfg, eventCh, logger)
	return s
}

// Start begins all monitoring goroutines.
func (s *WindowsSensor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel

	if err := s.process.Start(ctx); err != nil {
		cancel()
		return fmt.Errorf("windows sensor: start process monitor: %w", err)
	}
	if err := s.scheduler.Start(ctx); err != nil {
		s.logger.Warn("windows sensor: start scheduler monitor", zap.Error(err))
	}
	if err := s.registry.Start(ctx); err != nil {
		s.logger.Warn("windows sensor: start registry monitor", zap.Error(err))
	}

	s.wg.Add(1)
	go s.publishLoop(ctx)

	s.logger.Info("windows sensor: started", zap.String("hostname", s.cfg.Hostname))
	return nil
}

// Stop gracefully shuts down all monitoring goroutines.
func (s *WindowsSensor) Stop() error {
	if s.cancelFn != nil {
		s.cancelFn()
	}
	s.process.Stop()
	s.scheduler.Stop()
	s.registry.Stop()
	s.wg.Wait()
	s.logger.Info("windows sensor: stopped")
	return nil
}

// Platform returns the platform identifier.
func (s *WindowsSensor) Platform() string { return "windows" }

// HealthCheck returns nil if the sensor appears to be running correctly.
func (s *WindowsSensor) HealthCheck(_ context.Context) error {
	return nil
}

// publishLoop reads events from the channel and forwards them to the publisher.
func (s *WindowsSensor) publishLoop(ctx context.Context) {
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
				s.logger.Warn("windows sensor: publish event",
					zap.String("event_type", event.EventType),
					zap.Error(err),
				)
			}
		}
	}
}
