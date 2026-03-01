//go:build windows

// Package hostguardwindows implements the HostGuard sensor for Windows.
package hostguardwindows

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceInfo captures the state of a Windows service.
type ServiceInfo struct {
	Name        string
	DisplayName string
	BinaryPath  string
	StartType   string // auto, manual, disabled, boot, system
	State       string // running, stopped, paused
	Account     string // LocalSystem, NetworkService, LocalService, or custom
	Description string
	PID         uint32
	ServiceType uint32 // raw service type flags
}

// criticalWindowsServices is the list of services whose unexpected stop is
// considered a high-severity anomaly.
var criticalWindowsServices = []string{
	"wininit", "lsass", "services", "winlogon", "csrss", "smss", "svchost",
}

// ServicesMonitor watches the Windows Service Control Manager for new,
// modified, and suspicious service registrations.
type ServicesMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	baseline map[string]ServiceInfo // key: service name
	stopCh   chan struct{}
	mu       sync.RWMutex
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
}

// newServicesMonitor creates a ServicesMonitor that sends events to eventCh.
func newServicesMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *ServicesMonitor {
	return &ServicesMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		baseline: make(map[string]ServiceInfo),
		stopCh:   make(chan struct{}),
	}
}

// Start enumerates the baseline and begins polling the SCM.
func (m *ServicesMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	initial, err := m.snapshot()
	if err != nil {
		cancel()
		return fmt.Errorf("windows: services monitor initial snapshot: %w", err)
	}
	m.mu.Lock()
	m.baseline = initial
	m.mu.Unlock()

	interval := m.cfg.PollInterval * 6
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.poll(ctx)
			}
		}
	}()
	return nil
}

// Stop gracefully shuts down the ServicesMonitor.
func (m *ServicesMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll compares a fresh SCM snapshot against the baseline.
func (m *ServicesMonitor) poll(ctx context.Context) {
	current, err := m.snapshot()
	if err != nil {
		m.logger.Warn("windows: services snapshot", zap.Error(err))
		return
	}

	m.mu.Lock()
	last := m.baseline
	m.baseline = current
	m.mu.Unlock()

	// Detect new services.
	for name, svc := range current {
		if prev, existed := last[name]; !existed {
			indicators := serviceAnomalyIndicators(svc)
			m.emitStartupEvent(ctx, "startup_item_added", svc, indicators)
		} else {
			// Detect modifications.
			var changeIndicators []string
			if svc.BinaryPath != prev.BinaryPath {
				changeIndicators = append(changeIndicators, "service_binary_changed")
			}
			if svc.StartType != prev.StartType {
				changeIndicators = append(changeIndicators, "service_start_type_changed")
			}
			if len(changeIndicators) > 0 {
				m.emitStartupEvent(ctx, "startup_item_modified", svc, changeIndicators)
			}

			// Detect state transitions.
			if prev.State != svc.State {
				if svc.State == "running" {
					m.emitProcessEvent(ctx, "process_created", svc)
				} else if svc.State == "stopped" {
					m.emitProcessEvent(ctx, "process_terminated", svc)
					// Critical service stop check.
					if isCriticalService(svc.Name) {
						m.emitCriticalServiceStop(ctx, svc)
					}
				}
			}
		}
	}
}

// snapshot enumerates all services from the SCM.
func (m *ServicesMonitor) snapshot() (map[string]ServiceInfo, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("windows: connect to SCM: %w", err)
	}
	defer manager.Disconnect() //nolint:errcheck

	names, err := manager.ListServices()
	if err != nil {
		return nil, fmt.Errorf("windows: list services: %w", err)
	}

	result := make(map[string]ServiceInfo, len(names))
	for _, name := range names {
		svc, err := manager.OpenService(name)
		if err != nil {
			continue
		}
		cfg, err := svc.Config()
		if err != nil {
			svc.Close() //nolint:errcheck
			continue
		}
		status, err := svc.Query()
		if err != nil {
			svc.Close() //nolint:errcheck
			continue
		}
		svc.Close() //nolint:errcheck

		result[name] = ServiceInfo{
			Name:        name,
			DisplayName: cfg.DisplayName,
			BinaryPath:  cfg.BinaryPathName,
			StartType:   startTypeString(cfg.StartType),
			State:       stateString(uint32(status.State)),
			Account:     cfg.ServiceStartName,
			Description: cfg.Description,
			PID:         status.ProcessId,
			ServiceType: cfg.ServiceType,
		}
	}
	return result, nil
}

// serviceAnomalyIndicators returns anomaly indicators for a newly discovered service.
func serviceAnomalyIndicators(svc ServiceInfo) []string {
	var indicators []string

	pathLower := strings.ToLower(svc.BinaryPath)

	// Binary in user-writable or temporary location.
	// Use literal path fragments; Windows APIs return expanded paths.
	suspiciousPaths := []string{`\temp\`, `\appdata\`, `\users\`}
	for _, sp := range suspiciousPaths {
		if strings.Contains(pathLower, sp) {
			indicators = append(indicators, "service_suspicious_path")
			break
		}
	}

	// Unquoted path with spaces (binary planting risk).
	if strings.Contains(svc.BinaryPath, " ") && !strings.HasPrefix(svc.BinaryPath, `"`) {
		indicators = append(indicators, "service_unquoted_path")
	}

	// LocalSystem with no description.
	if strings.EqualFold(svc.Account, "LocalSystem") && svc.Description == "" {
		indicators = append(indicators, "service_localsystem_no_description")
	}

	// Interactive service (deprecated, suspicious).
	const serviceInteractiveProcess = 0x00000100
	if svc.ServiceType&serviceInteractiveProcess != 0 {
		indicators = append(indicators, "service_interactive")
	}

	// New kernel driver (Type 1 = kernel driver, Type 2 = file system driver).
	if svc.ServiceType == 1 || svc.ServiceType == 2 {
		indicators = append(indicators, "service_new_driver")
	}

	return indicators
}

// emitStartupEvent emits a startup_item_added or startup_item_modified event.
func (m *ServicesMonitor) emitStartupEvent(ctx context.Context, eventType string, svc ServiceInfo, indicators []string) {
	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "windows",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		StartupItem: &common.StartupItem{
			ID:      svc.Name,
			Name:    svc.DisplayName,
			Type:    "windows_service",
			Command: svc.BinaryPath,
			Source:  "SCM",
		},
		Indicators: indicators,
		RawData: map[string]interface{}{
			"service_account":    svc.Account,
			"service_start_type": svc.StartType,
			"service_state":      svc.State,
			"service_description": svc.Description,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// emitProcessEvent emits a process_created or process_terminated event for a service.
func (m *ServicesMonitor) emitProcessEvent(ctx context.Context, eventType string, svc ServiceInfo) {
	event := &common.HostEvent{
		EventType: eventType,
		Platform:  "windows",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		Process: &common.ProcessInfo{
			PID:  svc.PID,
			Name: svc.Name,
		},
		RawData: map[string]interface{}{
			"service_name":  svc.Name,
			"service_state": svc.State,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// emitCriticalServiceStop emits a T3 process_anomaly for an unexpected critical service stop.
func (m *ServicesMonitor) emitCriticalServiceStop(ctx context.Context, svc ServiceInfo) {
	event := &common.HostEvent{
		EventType: "process_anomaly",
		Platform:  "windows",
		Hostname:  m.cfg.Hostname,
		Timestamp: time.Now(),
		Process: &common.ProcessInfo{
			PID:  svc.PID,
			Name: svc.Name,
		},
		Indicators: []string{"critical_service_stopped"},
		RawData: map[string]interface{}{
			"service_name": svc.Name,
		},
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// isCriticalService returns true if the service name is in the critical list.
func isCriticalService(name string) bool {
	nameLower := strings.ToLower(name)
	for _, c := range criticalWindowsServices {
		if nameLower == c {
			return true
		}
	}
	return false
}

// startTypeString converts a Windows service start type constant to a human-readable string.
func startTypeString(t uint32) string {
	switch t {
	case 0:
		return "boot"
	case 1:
		return "system"
	case 2:
		return "auto"
	case 3:
		return "manual"
	case 4:
		return "disabled"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// stateString converts a Windows service state constant to a human-readable string.
func stateString(s uint32) string {
	switch s {
	case 1:
		return "stopped"
	case 2:
		return "start_pending"
	case 3:
		return "stop_pending"
	case 4:
		return "running"
	case 5:
		return "continue_pending"
	case 6:
		return "pause_pending"
	case 7:
		return "paused"
	default:
		return fmt.Sprintf("unknown(%d)", s)
	}
}
