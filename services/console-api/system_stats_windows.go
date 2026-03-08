//go:build windows

// system_stats_windows.go — Windows stub for the system stats endpoint.
// Full Windows performance counters are out of scope; we return zeroes and
// the logical CPU count so the frontend degrades gracefully.
package consoleapi

import (
	"net/http"
	"runtime"
	"time"
)

// SystemStats is the payload returned by GET /api/v1/system/stats.
type SystemStats struct {
	CPUUtilPct float64 `json:"cpu_util_pct"`
	CPUCores   int     `json:"cpu_cores"`
	LoadAvg1   float64 `json:"load_avg_1m"`
	LoadAvg5   float64 `json:"load_avg_5m"`
	LoadAvg15  float64 `json:"load_avg_15m"`
	MemTotalMB float64 `json:"mem_total_mb"`
	MemUsedMB  float64 `json:"mem_used_mb"`
	MemUsedPct float64 `json:"mem_used_pct"`
	SampledAt  string  `json:"sampled_at"`
}

func (s *Server) handleSystemStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, SystemStats{
		CPUUtilPct: -1,
		CPUCores:   runtime.NumCPU(),
		SampledAt:  time.Now().UTC().Format(time.RFC3339),
	})
}
