// Package consoleapi — supplychain.go provides the SupplyChainGuard console
// handlers: package-manager invocation events detected from HostGuard process
// telemetry, with basic typosquatting risk indicators.
package consoleapi

import (
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ─── Supply-chain event store ─────────────────────────────────────────────────

// scEvent is a single detected package-manager invocation.
type scEvent struct {
	ID          string  `json:"id"`
	Timestamp   string  `json:"timestamp"`
	Host        string  `json:"host"`
	Installer   string  `json:"installer"`   // npm, pip, go, apt, brew, cargo …
	PackageName string  `json:"package_name"`
	Version     string  `json:"version,omitempty"`
	RiskScore   float64 `json:"risk_score"`
	RiskLabel   string  `json:"risk_label"`
	Flags       []string `json:"flags,omitempty"` // e.g. ["typosquatting", "unknown_package"]
}

// scStore holds the in-memory supply-chain event log (ring buffer, max 2000).
type scStore struct {
	mu     sync.RWMutex
	events []*scEvent
	seq    int
}

func newSCStore() *scStore { return &scStore{} }

func (s *scStore) add(ev *scEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("sc-%d", s.seq)
	}
	s.events = append(s.events, ev)
	const maxEvents = 2000
	if len(s.events) > maxEvents {
		s.events = s.events[len(s.events)-maxEvents:]
	}
}

func (s *scStore) list(page, pageSize int) ([]*scEvent, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	total := len(s.events)
	if pageSize <= 0 || page <= 0 {
		return []*scEvent{}, total
	}
	start := (page - 1) * pageSize
	if start >= total {
		return []*scEvent{}, total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	out := make([]*scEvent, end-start)
	copy(out, s.events[start:end])
	return out, total
}

// ─── Typosquatting heuristic ──────────────────────────────────────────────────

// popularPackages is a small set of high-value targets for typosquatting.
var popularPackages = []string{
	"react", "lodash", "express", "axios", "webpack", "babel",
	"numpy", "pandas", "requests", "flask", "django", "tensorflow",
	"boto3", "sqlalchemy", "pytest", "black",
	"gin", "cobra", "viper", "echo", "fiber",
}

// levenshtein computes the edit distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	dp := make([][]int, la+1)
	for i := range dp {
		dp[i] = make([]int, lb+1)
		dp[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		dp[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			dp[i][j] = min3(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+cost)
		}
	}
	return dp[la][lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// isTyposquatting returns the closest popular package and true when the
// package name is within edit-distance 2 of a popular name but not an exact match.
func isTyposquatting(name string) (string, bool) {
	name = strings.ToLower(name)
	minDist := math.MaxInt32
	closest := ""
	for _, pop := range popularPackages {
		if name == pop {
			return "", false // exact match — not a typosquat
		}
		d := levenshtein(name, pop)
		if d < minDist {
			minDist = d
			closest = pop
		}
	}
	return closest, minDist <= 2 && minDist > 0
}

// ─── Event ingestion ──────────────────────────────────────────────────────────

// IngestProcessEvent checks whether an event from HostGuard represents a
// package-manager invocation and, if so, records it in the scStore.
// This is called from the main.go event pipeline for events with domain="host".
func (s *Server) IngestProcessEvent(event map[string]interface{}) {
	if s.scStore == nil {
		return
	}
	cmd, _ := event["command"].(string)
	if cmd == "" {
		cmd, _ = event["process_name"].(string)
	}
	installer := detectInstaller(cmd)
	if installer == "" {
		return
	}

	// Try to extract the package name from the command.
	pkg, version := parsePackageFromCmd(cmd, installer)

	flags := make([]string, 0)
	riskScore := 10.0
	if pkg != "" {
		if closest, squatting := isTyposquatting(pkg); squatting {
			flags = append(flags, fmt.Sprintf("typosquatting:%s", closest))
			riskScore += 40
		}
	} else {
		flags = append(flags, "unknown_package")
	}

	host, _ := event["hostname"].(string)
	if host == "" {
		host, _ = event["host"].(string)
	}

	riskLabel := "low"
	switch {
	case riskScore >= 60:
		riskLabel = "high"
	case riskScore >= 30:
		riskLabel = "medium"
	}

	s.scStore.add(&scEvent{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Host:        host,
		Installer:   installer,
		PackageName: pkg,
		Version:     version,
		RiskScore:   riskScore,
		RiskLabel:   riskLabel,
		Flags:       flags,
	})
}

// detectInstaller checks if a command string indicates a package manager.
func detectInstaller(cmd string) string {
	cmd = strings.ToLower(cmd)
	switch {
	case strings.HasPrefix(cmd, "npm ") || cmd == "npm":
		return "npm"
	case strings.HasPrefix(cmd, "pip ") || strings.HasPrefix(cmd, "pip3 "):
		return "pip"
	case strings.HasPrefix(cmd, "go get") || strings.HasPrefix(cmd, "go install"):
		return "go"
	case strings.HasPrefix(cmd, "apt install") || strings.HasPrefix(cmd, "apt-get install"):
		return "apt"
	case strings.HasPrefix(cmd, "brew install"):
		return "brew"
	case strings.HasPrefix(cmd, "cargo install") || strings.HasPrefix(cmd, "cargo add"):
		return "cargo"
	case strings.HasPrefix(cmd, "yarn add") || strings.HasPrefix(cmd, "yarn install"):
		return "yarn"
	default:
		return ""
	}
}

// parsePackageFromCmd extracts package name and optional version from a CLI command.
func parsePackageFromCmd(cmd, installer string) (pkg, version string) {
	cmd = strings.TrimSpace(cmd)
	parts := strings.Fields(cmd)
	switch installer {
	case "npm":
		// npm install <pkg>[@version]
		for i, p := range parts {
			if p == "install" || p == "i" {
				if i+1 < len(parts) {
					spec := parts[i+1]
					if idx := strings.LastIndex(spec, "@"); idx > 0 {
						return spec[:idx], spec[idx+1:]
					}
					return spec, ""
				}
			}
		}
	case "pip":
		// pip install <pkg>[==version]
		for i, p := range parts {
			if p == "install" {
				if i+1 < len(parts) {
					spec := parts[i+1]
					if idx := strings.Index(spec, "=="); idx > 0 {
						return spec[:idx], spec[idx+2:]
					}
					return spec, ""
				}
			}
		}
	case "go":
		// go get github.com/foo/bar@v1.2.3
		for _, p := range parts[2:] {
			if !strings.HasPrefix(p, "-") {
				if idx := strings.Index(p, "@"); idx > 0 {
					return p[:idx], p[idx+1:]
				}
				return p, ""
			}
		}
	case "cargo":
		for i, p := range parts {
			if p == "install" || p == "add" {
				if i+1 < len(parts) {
					return parts[i+1], ""
				}
			}
		}
	case "yarn":
		for i, p := range parts {
			if p == "add" {
				if i+1 < len(parts) {
					return parts[i+1], ""
				}
			}
		}
	case "brew", "apt":
		for i, p := range parts {
			if p == "install" {
				if i+1 < len(parts) {
					return parts[i+1], ""
				}
			}
		}
	}
	return "", ""
}

// ─── HTTP handlers ─────────────────────────────────────────────────────────────

// handleSupplyChain dispatches SupplyChainGuard API requests.
func (s *Server) handleSupplyChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil && n > 0 {
			page = n
		}
	}

	items, total := s.scStore.list(page, 50)
	if items == nil {
		items = []*scEvent{}
	}

	// Aggregate stats.
	highRisk := 0
	installers := map[string]int{}
	for _, ev := range s.scStore.events {
		if ev.RiskScore >= 30 {
			highRisk++
		}
		installers[ev.Installer]++
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events":     items,
		"page":       page,
		"total":      total,
		"high_risk":  highRisk,
		"installers": installers,
	})
}

// handleSupplyChainStats returns aggregate supply-chain statistics.
func (s *Server) handleSupplyChainStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.scStore.mu.RLock()
	total := len(s.scStore.events)
	highRisk, typosquatting, uniqueHosts := 0, 0, map[string]struct{}{}
	installers := map[string]int{}
	for _, ev := range s.scStore.events {
		if ev.RiskScore >= 30 {
			highRisk++
		}
		for _, f := range ev.Flags {
			if strings.HasPrefix(f, "typosquatting:") {
				typosquatting++
				break
			}
		}
		if ev.Host != "" {
			uniqueHosts[ev.Host] = struct{}{}
		}
		installers[ev.Installer]++
	}
	s.scStore.mu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_events":      total,
		"high_risk_events":  highRisk,
		"typosquatting":     typosquatting,
		"unique_hosts":      len(uniqueHosts),
		"by_installer":      installers,
	})
}
