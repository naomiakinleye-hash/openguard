// Package hostguardcommon provides shared types and utilities for the HostGuard sensor.
package hostguardcommon

import (
	"sync"
	"time"
)

// cpuSample holds a single CPU usage reading at a point in time.
type cpuSample struct {
	cpuPercent float64
	ts         time.Time
}

// timestampedEvent records the time of a discrete event (process spawn, network connection).
type timestampedEvent struct {
	ts time.Time
}

// pidMetrics holds per-PID time-windowed metrics for low-and-slow detection.
type pidMetrics struct {
	cpuSamples      []cpuSample
	processSpawns   []timestampedEvent
	networkConns    []timestampedEvent
}

// LowSlowDetector tracks per-PID time-windowed metrics to detect low-and-slow attacks.
// It maintains a sliding window of CPU samples, process spawn events, and network connection
// events per PID to identify sustained low-level malicious activity.
type LowSlowDetector struct {
	windowSize time.Duration
	mu         sync.Mutex
	metrics    map[uint32]*pidMetrics
}

// NewLowSlowDetector creates a new LowSlowDetector with the given window size.
// If windowSize is zero, it defaults to 5 minutes.
func NewLowSlowDetector(windowSize time.Duration) *LowSlowDetector {
	if windowSize <= 0 {
		windowSize = 5 * time.Minute
	}
	return &LowSlowDetector{
		windowSize: windowSize,
		metrics:    make(map[uint32]*pidMetrics),
	}
}

// RecordCPUSample records a CPU usage sample for a PID at the given time.
func (d *LowSlowDetector) RecordCPUSample(pid uint32, cpuPercent float64, ts time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.getOrCreate(pid)
	m.cpuSamples = append(m.cpuSamples, cpuSample{cpuPercent: cpuPercent, ts: ts})
	d.pruneOldCPUSamples(m, ts)
}

// RecordProcessSpawn records a child process spawn event for a parent PID.
func (d *LowSlowDetector) RecordProcessSpawn(parentPID uint32, ts time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.getOrCreate(parentPID)
	m.processSpawns = append(m.processSpawns, timestampedEvent{ts: ts})
	d.pruneOldEvents(&m.processSpawns, ts)
}

// RecordNetworkConnection records a network connection event for a PID.
func (d *LowSlowDetector) RecordNetworkConnection(pid uint32, ts time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.getOrCreate(pid)
	m.networkConns = append(m.networkConns, timestampedEvent{ts: ts})
	d.pruneOldEvents(&m.networkConns, ts)
}

// Evaluate checks the recorded metrics for a PID and returns any triggered indicators.
// Returns nil if no indicators are triggered.
func (d *LowSlowDetector) Evaluate(pid uint32) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	m, ok := d.metrics[pid]
	if !ok {
		return nil
	}

	var indicators []string
	now := time.Now()

	// Check persistent low CPU: average CPU between 5% and 20% sustained over full window.
	if len(m.cpuSamples) >= 2 {
		oldest := m.cpuSamples[0].ts
		windowFilled := now.Sub(oldest) >= d.windowSize
		if windowFilled {
			var sum float64
			for _, s := range m.cpuSamples {
				sum += s.cpuPercent
			}
			avg := sum / float64(len(m.cpuSamples))
			if avg >= 5.0 && avg <= 20.0 {
				indicators = append(indicators, "low_and_slow_cpu")
			}
		}
	}

	// Check process spawn burst: more than 10 child spawns within window.
	if len(m.processSpawns) > 10 {
		indicators = append(indicators, "process_spawn_burst")
	}

	// Check network connection burst: more than 100 connections within window.
	if len(m.networkConns) > 100 {
		indicators = append(indicators, "network_connection_burst")
	}

	return indicators
}

// getOrCreate returns the pidMetrics for a PID, creating it if necessary.
// Caller must hold d.mu.
func (d *LowSlowDetector) getOrCreate(pid uint32) *pidMetrics {
	if m, ok := d.metrics[pid]; ok {
		return m
	}
	m := &pidMetrics{}
	d.metrics[pid] = m
	return m
}

// pruneOldCPUSamples removes CPU samples older than the window from the metric.
// Caller must hold d.mu.
func (d *LowSlowDetector) pruneOldCPUSamples(m *pidMetrics, now time.Time) {
	cutoff := now.Add(-d.windowSize)
	i := 0
	for i < len(m.cpuSamples) && m.cpuSamples[i].ts.Before(cutoff) {
		i++
	}
	if i > 0 {
		m.cpuSamples = m.cpuSamples[i:]
	}
}

// pruneOldEvents removes timestamped events older than the window.
// Caller must hold d.mu.
func (d *LowSlowDetector) pruneOldEvents(events *[]timestampedEvent, now time.Time) {
	cutoff := now.Add(-d.windowSize)
	i := 0
	for i < len(*events) && (*events)[i].ts.Before(cutoff) {
		i++
	}
	if i > 0 {
		*events = (*events)[i:]
	}
}
