//go:build linux

// Package hostguardlinux implements the HostGuard sensor for Linux.
package hostguardlinux

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/hostguard/common"
	"go.uber.org/zap"
)

// pidSample holds one CPU/memory reading for a PID.
type pidSample struct {
	cpuJiffies uint64
	memoryMB   float64
	wallTime   time.Time
}

// ResourceMonitor polls /proc/<pid>/stat and /proc/<pid>/status for CPU and
// memory usage, emitting resource_spike events when thresholds are exceeded for
// two consecutive samples.
type ResourceMonitor struct {
	cfg       common.Config
	eventCh   chan<- *common.HostEvent
	logger    *zap.Logger
	samples   map[uint32][]pidSample // rolling window: last 2 samples per PID
	mu        sync.Mutex
	cancelFn  context.CancelFunc
	wg        sync.WaitGroup
	lowSlow   *common.LowSlowDetector
}

// newResourceMonitor creates a ResourceMonitor that sends events to eventCh.
func newResourceMonitor(cfg common.Config, eventCh chan<- *common.HostEvent, logger *zap.Logger) *ResourceMonitor {
	return &ResourceMonitor{
		cfg:     cfg,
		eventCh: eventCh,
		logger:  logger,
		samples: make(map[uint32][]pidSample),
		lowSlow: common.NewLowSlowDetector(0),
	}
}

// Start begins polling at the configured interval.
func (m *ResourceMonitor) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	m.cancelFn = cancel

	interval := m.cfg.PollInterval
	if interval <= 0 {
		interval = 5 * time.Second
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

// Stop gracefully shuts down the ResourceMonitor.
func (m *ResourceMonitor) Stop() {
	if m.cancelFn != nil {
		m.cancelFn()
	}
	m.wg.Wait()
}

// poll reads /proc for all PIDs and checks CPU/memory thresholds.
func (m *ResourceMonitor) poll(ctx context.Context) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		m.logger.Warn("linux: resource monitor readdir /proc", zap.Error(err))
		return
	}

	numCPUs := float64(runtime.NumCPU())
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	activePIDs := make(map[uint32]struct{})
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		activePIDs[pid] = struct{}{}

		jiffies, err := readProcStatJiffies(pid)
		if err != nil {
			continue
		}
		memMB, err := readProcStatusMemMB(pid)
		if err != nil {
			continue
		}

		sample := pidSample{cpuJiffies: jiffies, memoryMB: memMB, wallTime: now}
		window := m.samples[pid]
		window = append(window, sample)
		if len(window) > 3 {
			window = window[len(window)-3:]
		}
		m.samples[pid] = window

		if len(window) < 2 {
			continue
		}

		// Compute CPU% from the last two samples.
		prev := window[len(window)-2]
		curr := window[len(window)-1]
		elapsed := curr.wallTime.Sub(prev.wallTime).Seconds()
		if elapsed <= 0 {
			continue
		}
		const hz = 100.0 // USER_HZ on Linux
		cpuPct := float64(curr.cpuJiffies-prev.cpuJiffies) / hz / elapsed * 100.0 * numCPUs

		// Record CPU sample for low-and-slow detection.
		m.lowSlow.RecordCPUSample(pid, cpuPct, now)
		if indicators := m.lowSlow.Evaluate(pid); len(indicators) > 0 {
			procName := readProcName(pid)
			lowSlowEvent := &common.HostEvent{
				EventType: "low_and_slow_anomaly",
				Platform:  "linux",
				Hostname:  m.cfg.Hostname,
				Timestamp: now,
				Process: &common.ProcessInfo{
					PID:        pid,
					Name:       procName,
					CPUPercent: cpuPct,
				},
				Indicators: indicators,
			}
			select {
			case m.eventCh <- lowSlowEvent:
			case <-ctx.Done():
				return
			}
		}

		cpuHigh := cpuPct > m.cfg.AnomalyThresholds.CPUPercentHigh
		memHigh := curr.memoryMB > m.cfg.AnomalyThresholds.MemoryMBHigh

		if !cpuHigh && !memHigh {
			continue
		}

		// Require 2 consecutive exceedances to avoid transient false positives.
		// We need 3 samples to check the previous CPU interval.
		var prevCPUHigh bool
		if len(window) >= 3 {
			older := window[len(window)-3]
			olderElapsed := prev.wallTime.Sub(older.wallTime).Seconds()
			if olderElapsed > 0 {
				prevCPU := float64(prev.cpuJiffies-older.cpuJiffies) / hz / olderElapsed * 100.0 * numCPUs
				prevCPUHigh = prevCPU > m.cfg.AnomalyThresholds.CPUPercentHigh
			}
		}
		prevMemHigh := prev.memoryMB > m.cfg.AnomalyThresholds.MemoryMBHigh

		// Skip if neither condition has been high for 2 consecutive samples.
		if cpuHigh && !prevCPUHigh && !(memHigh && prevMemHigh) {
			continue
		}
		if memHigh && !prevMemHigh && !(cpuHigh && prevCPUHigh) {
			continue
		}

		procName := readProcName(pid)
		event := &common.HostEvent{
			EventType: "resource_spike",
			Platform:  "linux",
			Hostname:  m.cfg.Hostname,
			Timestamp: now,
			Process: &common.ProcessInfo{
				PID:        pid,
				Name:       procName,
				CPUPercent: cpuPct,
				MemoryMB:   curr.memoryMB,
			},
			Indicators: []string{"resource_spike"},
			RawData: map[string]interface{}{
				"cpu_percent": fmt.Sprintf("%.2f", cpuPct),
				"memory_mb":   fmt.Sprintf("%.2f", curr.memoryMB),
			},
		}
		select {
		case m.eventCh <- event:
		case <-ctx.Done():
			return
		}
	}

	// Clean up stale PIDs.
	for pid := range m.samples {
		if _, ok := activePIDs[pid]; !ok {
			delete(m.samples, pid)
		}
	}
}

// readProcStatJiffies reads the total CPU jiffies (utime+stime) for a PID.
func readProcStatJiffies(pid uint32) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 15 {
		return 0, fmt.Errorf("linux: /proc/%d/stat: too few fields", pid)
	}
	utime, err := strconv.ParseUint(fields[13], 10, 64)
	if err != nil {
		return 0, err
	}
	stime, err := strconv.ParseUint(fields[14], 10, 64)
	if err != nil {
		return 0, err
	}
	return utime + stime, nil
}

// readProcStatusMemMB reads VmRSS from /proc/<pid>/status and returns it in MB.
func readProcStatusMemMB(pid uint32) (float64, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				continue
			}
			return float64(kb) / 1024.0, nil
		}
	}
	return 0, fmt.Errorf("linux: VmRSS not found in /proc/%d/status", pid)
}
