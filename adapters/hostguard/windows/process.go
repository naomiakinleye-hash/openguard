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
	"github.com/StackExchange/wmi"
	"go.uber.org/zap"
)

// win32Process maps to WMI Win32_Process fields.
type win32Process struct {
	ProcessId       uint32
	ParentProcessId uint32
	Name            string
	ExecutablePath  string
	CommandLine     string
	WorkingSetSize  uint64
}

// windowsProcessSnapshot holds a snapshot of a Windows process.
type windowsProcessSnapshot struct {
	info common.ProcessInfo
}

// ProcessMonitor watches Windows processes via WMI for lifecycle events and anomalies.
type ProcessMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	mu       sync.Mutex
	lastPIDs map[uint32]windowsProcessSnapshot
	cancelFn context.CancelFunc
	wg       sync.WaitGroup
	browser  *common.BrowserActivityAnalyzer
}

// newProcessMonitor creates a ProcessMonitor that sends events to eventCh.
func newProcessMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *ProcessMonitor {
	return &ProcessMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		lastPIDs: make(map[uint32]windowsProcessSnapshot),
		browser:  common.NewBrowserActivityAnalyzer(),
	}
}

// Start begins polling processes at the configured interval.
func (m *ProcessMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(m.cfg.PollInterval)
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

// Stop gracefully shuts down the ProcessMonitor.
func (m *ProcessMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll enumerates processes via WMI and emits HostEvents.
func (m *ProcessMonitor) poll(ctx context.Context) {
	var procs []win32Process
	query := "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, WorkingSetSize FROM Win32_Process"
	if err := wmi.Query(query, &procs); err != nil {
		m.logger.Warn("windows: WMI query", zap.Error(err))
		return
	}

	current := make(map[uint32]windowsProcessSnapshot)
	for _, p := range procs {
		current[p.ProcessId] = windowsProcessSnapshot{
			info: common.ProcessInfo{
				PID:      p.ProcessId,
				PPID:     p.ParentProcessId,
				Name:     p.Name,
				ExePath:  p.ExecutablePath,
				CmdLine:  p.CommandLine,
				MemoryMB: float64(p.WorkingSetSize) / (1024 * 1024),
			},
		}
	}

	m.mu.Lock()
	last := m.lastPIDs
	m.lastPIDs = current
	m.mu.Unlock()

	newCount := 0
	for pid, snap := range current {
		if _, existed := last[pid]; !existed {
			newCount++
			m.emitEvent(ctx, "process_created", &snap.info, nil)
			m.checkAnomalies(ctx, &snap.info)
		}
		if indicators := m.browser.AnalyzeProcess(&snap.info); len(indicators) > 0 {
			m.emitEvent(ctx, "browser_anomaly", &snap.info, indicators)
		}
	}
	for pid, snap := range last {
		if _, exists := current[pid]; !exists {
			m.emitEvent(ctx, "process_terminated", &snap.info, nil)
		}
	}
	if newCount >= m.cfg.AnomalyThresholds.NewProcessBurst {
		m.logger.Warn("windows: process burst detected", zap.Int("new_processes", newCount))
	}
}

// checkAnomalies inspects a process for suspicious Windows-specific indicators.
func (m *ProcessMonitor) checkAnomalies(ctx context.Context, info *common.ProcessInfo) {
	var indicators []string

	exeLower := strings.ToLower(info.ExePath)

	// Suspicious exe paths (case-insensitive on Windows).
	suspiciousPaths := append(m.cfg.SuspiciousPaths, []string{
		`%temp%`, `%appdata%`, `c:\users`, `c:\windows\temp`,
	}...)
	for _, sp := range suspiciousPaths {
		if strings.Contains(exeLower, strings.ToLower(sp)) {
			indicators = append(indicators, "suspicious_path")
			break
		}
	}

	// Masquerading: svchost.exe not in System32.
	if strings.EqualFold(info.Name, "svchost.exe") &&
		!strings.Contains(exeLower, `c:\windows\system32`) {
		indicators = append(indicators, "masquerading")
	}

	// Unusual parent-child.
	if isWindowsShell(info.Name) {
		parent := m.parentName(info.PPID)
		if isWindowsOfficeOrBrowser(parent) {
			indicators = append(indicators, "unusual_parent_child")
		}
	}

	// High memory.
	if info.MemoryMB > m.cfg.AnomalyThresholds.MemoryMBHigh {
		indicators = append(indicators, "resource_spike")
	}

	if len(indicators) == 0 {
		return
	}

	eventType := "process_anomaly"
	for _, ind := range indicators {
		if ind == "masquerading" {
			eventType = "process_anomaly"
			break
		}
	}

	m.emitEvent(ctx, eventType, info, indicators)
}

// emitEvent sends a HostEvent onto the event channel.
func (m *ProcessMonitor) emitEvent(ctx context.Context, eventType string, info *common.ProcessInfo, indicators []string) {
	event := &common.HostEvent{
		EventType:  eventType,
		Platform:   "windows",
		Hostname:   m.cfg.Hostname,
		Timestamp:  time.Now(),
		Process:    info,
		Indicators: indicators,
	}
	select {
	case m.eventCh <- event:
	case <-ctx.Done():
	}
}

// parentName returns the process name of the given PID from the last snapshot.
func (m *ProcessMonitor) parentName(ppid uint32) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if snap, ok := m.lastPIDs[ppid]; ok {
		return snap.info.Name
	}
	return ""
}

func isWindowsShell(name string) bool {
	lower := strings.ToLower(name)
	return lower == "cmd.exe" || lower == "powershell.exe" || lower == "pwsh.exe"
}

func isWindowsOfficeOrBrowser(name string) bool {
	lower := strings.ToLower(name)
	for _, app := range []string{"winword.exe", "excel.exe", "outlook.exe", "chrome.exe", "firefox.exe"} {
		if lower == app {
			return true
		}
	}
	return false
}

// SchedulerMonitor is declared here to avoid circular references.
// Its implementation is in scheduler.go.

// RegistryMonitor is declared here to avoid circular references.
// Its implementation is in registry.go.

// windowsSensor errors.
var errWMIUnavailable = fmt.Errorf("windows: WMI unavailable")
