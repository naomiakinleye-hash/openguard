//go:build !windows

// system_stats.go — cross-platform (Linux/macOS) system resource statistics
// for the /api/v1/system/stats endpoint.
package consoleapi

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// cpuSnapshot stores a single reading of aggregate CPU jiffies (Linux only).
type cpuSnapshot struct {
	total uint64
	idle  uint64
	ts    time.Time
}

// cpuTracker holds the last two snapshots so we can compute a delta-based
// utilisation percentage.
type cpuTracker struct {
	mu   sync.Mutex
	prev cpuSnapshot
	cur  cpuSnapshot
}

var globalCPUTracker = &cpuTracker{}

// readCPUStat reads the first "cpu" line from /proc/stat and returns (total
// jiffies, idle jiffies).  Returns an error on non-Linux platforms where
// /proc/stat is absent.
func readCPUStat() (total, idle uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close() //nolint:errcheck

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			break
		}
		// fields: cpu user nice system idle iowait irq softirq steal ...
		nums := make([]uint64, len(fields)-1)
		for i, s := range fields[1:] {
			nums[i], _ = strconv.ParseUint(s, 10, 64)
		}
		idleVal := nums[3] // idle
		if len(nums) > 4 {
			idleVal += nums[4] // iowait counts as idle for utilisation purposes
		}
		for _, v := range nums {
			total += v
		}
		return total, idleVal, nil
	}
	return 0, 0, fmt.Errorf("cpu line not found in /proc/stat")
}

// sampleCPU takes a fresh /proc/stat snapshot and updates the tracker.
func (t *cpuTracker) sample() {
	total, idle, err := readCPUStat()
	if err != nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prev = t.cur
	t.cur = cpuSnapshot{total: total, idle: idle, ts: time.Now()}
}

// utilPct returns the CPU utilisation percentage derived from the last two
// snapshots.  Returns -1 if not enough data is available yet.
func (t *cpuTracker) utilPct() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.prev.total == 0 {
		return -1
	}
	dTotal := float64(t.cur.total - t.prev.total)
	dIdle := float64(t.cur.idle - t.prev.idle)
	if dTotal <= 0 {
		return 0
	}
	return (1 - dIdle/dTotal) * 100
}

// readLoadAvg reads /proc/loadavg and returns the 1-, 5-, 15-minute load
// averages.  Returns zeros on platforms that lack /proc/loadavg.
func readLoadAvg() (load1, load5, load15 float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		load1, _ = strconv.ParseFloat(fields[0], 64)
		load5, _ = strconv.ParseFloat(fields[1], 64)
		load15, _ = strconv.ParseFloat(fields[2], 64)
	}
	return
}

// readMemInfo reads selected fields from /proc/meminfo and returns totals in MB.
func readMemInfo() (totalMB, availMB float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close() //nolint:errcheck

	sc := bufio.NewScanner(f)
	var totalKB, availKB uint64
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				totalKB, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		case strings.HasPrefix(line, "MemAvailable:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				availKB, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
		if totalKB > 0 && availKB > 0 {
			break
		}
	}
	return float64(totalKB) / 1024, float64(availKB) / 1024
}

// SystemStats is the payload returned by GET /api/v1/system/stats.
type SystemStats struct {
	// CPU fields
	CPUUtilPct float64 `json:"cpu_util_pct"`   // 0–100 %, -1 if not yet available
	CPUCores   int     `json:"cpu_cores"`       // logical CPU count
	LoadAvg1   float64 `json:"load_avg_1m"`
	LoadAvg5   float64 `json:"load_avg_5m"`
	LoadAvg15  float64 `json:"load_avg_15m"`
	// Memory fields
	MemTotalMB float64 `json:"mem_total_mb"`
	MemUsedMB  float64 `json:"mem_used_mb"`
	MemUsedPct float64 `json:"mem_used_pct"` // 0–100 %
	// Housekeeping
	SampledAt string `json:"sampled_at"` // RFC-3339
}

// handleSystemStats handles GET /api/v1/system/stats.
// It takes a fresh /proc/stat sample on every call and returns utilisation
// computed from the delta with the previous sample.
func (s *Server) handleSystemStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Take a new CPU sample (the first call will prime the tracker; utilPct
	// will return -1 until the second call arrives).
	globalCPUTracker.sample()
	cpuPct := globalCPUTracker.utilPct()

	load1, load5, load15 := readLoadAvg()
	totalMB, availMB := readMemInfo()
	usedMB := totalMB - availMB
	var memPct float64
	if totalMB > 0 {
		memPct = usedMB / totalMB * 100
	}

	stats := SystemStats{
		CPUUtilPct: cpuPct,
		CPUCores:   runtime.NumCPU(),
		LoadAvg1:   load1,
		LoadAvg5:   load5,
		LoadAvg15:  load15,
		MemTotalMB: totalMB,
		MemUsedMB:  usedMB,
		MemUsedPct: memPct,
		SampledAt:  time.Now().UTC().Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, stats)
}
