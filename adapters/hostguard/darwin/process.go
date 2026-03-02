//go:build darwin

// Package hostguarddarwin implements the HostGuard sensor for macOS.
package hostguarddarwin

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// darwinProcessSnapshot holds a snapshot of a single process on macOS.
type darwinProcessSnapshot struct {
	info common.ProcessInfo
}

// ProcessMonitor watches macOS processes for lifecycle events and anomalies.
type ProcessMonitor struct {
	cfg      common.Config
	eventCh  chan<- *common.HostEvent
	logger   *zap.Logger
	mu       sync.Mutex
	lastPIDs map[uint32]darwinProcessSnapshot
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
		lastPIDs: make(map[uint32]darwinProcessSnapshot),
		browser:  common.NewBrowserActivityAnalyzer(),
	}
}

// Start begins polling for processes at the configured interval.
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

// poll enumerates running processes via ps and emits HostEvents.
func (m *ProcessMonitor) poll(ctx context.Context) {
	procs, err := listProcesses()
	if err != nil {
		m.logger.Warn("darwin: list processes", zap.Error(err))
		return
	}

	current := make(map[uint32]darwinProcessSnapshot)
	for _, p := range procs {
		current[p.info.PID] = p
	}

	m.mu.Lock()
	last := m.lastPIDs
	m.lastPIDs = current
	m.mu.Unlock()

	for pid, snap := range current {
		if _, existed := last[pid]; !existed {
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
}

// checkAnomalies inspects a process for suspicious indicators.
func (m *ProcessMonitor) checkAnomalies(ctx context.Context, info *common.ProcessInfo) {
	var indicators []string

	exeLower := strings.ToLower(info.ExePath)
	for _, sp := range m.cfg.SuspiciousPaths {
		if strings.HasPrefix(exeLower, strings.ToLower(sp)) {
			indicators = append(indicators, "suspicious_path")
			break
		}
	}
	// Hidden process name.
	if strings.HasPrefix(info.Name, ".") {
		indicators = append(indicators, "suspicious_path")
	}
	// Unusual parent-child: shell spawned by browser or Office.
	if isDarwinShell(info.Name) {
		parent := m.parentName(info.PPID)
		if isDarwinBrowser(parent) || isDarwinOffice(parent) {
			indicators = append(indicators, "unusual_parent_child")
		}
	}
	// Privilege escalation.
	if isDarwinPrivEsc(info.Name) {
		indicators = append(indicators, "sudo_invocation")
	}
	// High CPU.
	if info.CPUPercent > m.cfg.AnomalyThresholds.CPUPercentHigh {
		indicators = append(indicators, "resource_spike")
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
		if ind == "sudo_invocation" {
			eventType = "privilege_escalation"
			break
		}
	}

	m.emitEvent(ctx, eventType, info, indicators)
}

// emitEvent sends a HostEvent onto the event channel.
func (m *ProcessMonitor) emitEvent(ctx context.Context, eventType string, info *common.ProcessInfo, indicators []string) {
	event := &common.HostEvent{
		EventType:  eventType,
		Platform:   "darwin",
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

// listProcesses runs ps and parses the output into process snapshots.
func listProcesses() ([]darwinProcessSnapshot, error) {
	cmd := exec.Command("ps", "-axo", "pid,ppid,user,%cpu,rss,stat,comm,args")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("darwin: ps: %w", err)
	}

	var procs []darwinProcessSnapshot
	scanner := bufio.NewScanner(bytes.NewReader(out))
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // skip header
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 7 {
			continue
		}
		pid, _ := strconv.ParseUint(fields[0], 10, 32)
		ppid, _ := strconv.ParseUint(fields[1], 10, 32)
		cpu, _ := strconv.ParseFloat(fields[3], 64)
		rssKB, _ := strconv.ParseUint(fields[4], 10, 64)
		comm := fields[6]
		args := ""
		if len(fields) > 7 {
			args = strings.Join(fields[7:], " ")
		}

		procs = append(procs, darwinProcessSnapshot{
			info: common.ProcessInfo{
				PID:        uint32(pid),
				PPID:       uint32(ppid),
				Username:   fields[2],
				CPUPercent: cpu,
				MemoryMB:   float64(rssKB) / 1024.0,
				Status:     fields[5],
				Name:       comm,
				ExePath:    comm,
				CmdLine:    args,
			},
		})
	}
	return procs, nil
}

func isDarwinShell(name string) bool {
	for _, s := range []string{"bash", "sh", "zsh", "fish", "dash"} {
		if name == s {
			return true
		}
	}
	return false
}

func isDarwinBrowser(name string) bool {
	for _, b := range []string{"Google Chrome", "firefox", "Safari", "chrome"} {
		if strings.Contains(name, b) {
			return true
		}
	}
	return false
}

func isDarwinOffice(name string) bool {
	for _, o := range []string{"Microsoft Word", "Microsoft Excel", "Numbers", "Pages"} {
		if strings.Contains(name, o) {
			return true
		}
	}
	return false
}

func isDarwinPrivEsc(name string) bool {
	for _, b := range []string{"sudo", "su"} {
		if name == b {
			return true
		}
	}
	return false
}
