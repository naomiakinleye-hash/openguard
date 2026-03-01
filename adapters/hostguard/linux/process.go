//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// processSnapshot holds a snapshot of a single process read from /proc.
type processSnapshot struct {
	info common.ProcessInfo
}

// ProcessMonitor watches /proc for process lifecycle events and anomalies.
type ProcessMonitor struct {
	cfg       common.Config
	eventCh   chan<- *common.HostEvent
	logger    *zap.Logger
	mu        sync.Mutex
	lastPIDs  map[uint32]processSnapshot
	cancelFn  context.CancelFunc
	wg        sync.WaitGroup
}

// newProcessMonitor creates a ProcessMonitor that sends events to eventCh.
func newProcessMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *ProcessMonitor {
	return &ProcessMonitor{
		cfg:      cfg,
		eventCh:  eventCh,
		logger:   logger,
		lastPIDs: make(map[uint32]processSnapshot),
	}
}

// Start begins polling /proc at the configured interval.
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

// poll enumerates /proc entries and emits HostEvents for new/terminated/anomalous processes.
func (m *ProcessMonitor) poll(ctx context.Context) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		m.logger.Warn("linux: readdir /proc", zap.Error(err))
		return
	}

	current := make(map[uint32]processSnapshot)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		snap, err := readProcInfo(uint32(pid))
		if err != nil {
			continue
		}
		current[uint32(pid)] = snap
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
	}
	for pid, snap := range last {
		if _, exists := current[pid]; !exists {
			m.emitEvent(ctx, "process_terminated", &snap.info, nil)
		}
	}
	if newCount >= m.cfg.AnomalyThresholds.NewProcessBurst {
		m.logger.Warn("linux: process burst detected", zap.Int("new_processes", newCount))
	}
}

// checkAnomalies inspects a ProcessInfo for suspicious indicators.
func (m *ProcessMonitor) checkAnomalies(ctx context.Context, info *common.ProcessInfo) {
	var indicators []string

	exeLower := strings.ToLower(info.ExePath)
	for _, sp := range m.cfg.SuspiciousPaths {
		if strings.HasPrefix(exeLower, strings.ToLower(sp)) {
			indicators = append(indicators, "suspicious_path")
			break
		}
	}
	// Deleted executable symlink.
	if strings.Contains(info.ExePath, "(deleted)") {
		indicators = append(indicators, "suspicious_path")
	}
	// Hidden process name.
	if strings.HasPrefix(info.Name, ".") {
		indicators = append(indicators, "suspicious_path")
	}
	// Unusual parent-child: shell spawned by web server.
	if isShell(info.Name) {
		parent := m.parentName(info.PPID)
		if isWebServer(parent) {
			indicators = append(indicators, "unusual_parent_child")
		}
	}
	// Privilege escalation indicators.
	if isPrivEscBinary(info.Name) {
		indicators = append(indicators, "sudo_invocation")
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
		if ind == "sudo_invocation" || ind == "setuid_execution" {
			eventType = "privilege_escalation"
			break
		}
	}

	event := &common.HostEvent{
		EventType:  eventType,
		Platform:   "linux",
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

// emitEvent sends a HostEvent onto the event channel.
func (m *ProcessMonitor) emitEvent(ctx context.Context, eventType string, info *common.ProcessInfo, indicators []string) {
	event := &common.HostEvent{
		EventType:  eventType,
		Platform:   "linux",
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

// parentName returns the process name of the given PID, or empty string on error.
func (m *ProcessMonitor) parentName(ppid uint32) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if snap, ok := m.lastPIDs[ppid]; ok {
		return snap.info.Name
	}
	return ""
}

// readProcInfo reads process information from /proc/<pid>/.
func readProcInfo(pid uint32) (processSnapshot, error) {
	dir := fmt.Sprintf("/proc/%d", pid)
	status, err := readProcStatus(dir)
	if err != nil {
		return processSnapshot{}, err
	}

	exePath, _ := os.Readlink(filepath.Join(dir, "exe"))
	cmdlineRaw, _ := os.ReadFile(filepath.Join(dir, "cmdline"))
	cmdline := strings.ReplaceAll(string(cmdlineRaw), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)

	return processSnapshot{
		info: common.ProcessInfo{
			PID:      pid,
			PPID:     status.ppid,
			Name:     status.name,
			ExePath:  exePath,
			CmdLine:  cmdline,
			MemoryMB: float64(status.vmRSSKB) / 1024.0,
			Status:   status.state,
		},
	}, nil
}

type procStatus struct {
	name     string
	ppid     uint32
	vmRSSKB  uint64
	state    string
}

// readProcStatus parses /proc/<pid>/status.
func readProcStatus(dir string) (procStatus, error) {
	f, err := os.Open(filepath.Join(dir, "status"))
	if err != nil {
		return procStatus{}, err
	}
	defer f.Close() //nolint:errcheck

	var s procStatus
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		switch key {
		case "Name":
			s.name = val
		case "PPid":
			if n, err := strconv.ParseUint(val, 10, 32); err == nil {
				s.ppid = uint32(n)
			}
		case "VmRSS":
			fields := strings.Fields(val)
			if len(fields) > 0 {
				if n, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
					s.vmRSSKB = n
				}
			}
		case "State":
			if len(val) > 0 {
				s.state = string(val[0])
			}
		}
	}
	if s.name == "" {
		return procStatus{}, fmt.Errorf("empty process name in %s/status", dir)
	}
	return s, nil
}

func isShell(name string) bool {
	shells := []string{"bash", "sh", "zsh", "fish", "dash", "ksh"}
	for _, s := range shells {
		if name == s {
			return true
		}
	}
	return false
}

func isWebServer(name string) bool {
	servers := []string{"nginx", "apache2", "httpd", "lighttpd"}
	for _, s := range servers {
		if name == s {
			return true
		}
	}
	return false
}

func isPrivEscBinary(name string) bool {
	binaries := []string{"sudo", "su", "pkexec", "doas"}
	for _, b := range binaries {
		if name == b {
			return true
		}
	}
	return false
}
