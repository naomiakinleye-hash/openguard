// kpi.go — GET /api/v1/stats/kpi
//
// Computes key performance indicator aggregates from the full EventStore and
// IncidentStore in a single pass, so the dashboard KPI charts always reflect
// all events rather than just the first page returned by /api/v1/events.
package consoleapi

import (
	"net/http"
	"time"
)

// KPITierStat is a single tier label and its event count.
type KPITierStat struct {
	Tier  string `json:"tier"`
	Count int    `json:"count"`
}

// KPIRiskBand is a risk-score range label and its event count.
type KPIRiskBand struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

// KPIIncidentStatus is an incident status label and its count.
type KPIIncidentStatus struct {
	Status string `json:"status"`
	Count  int    `json:"count"`
}

// KPIGuardThreats is the threat count for a single guard domain.
type KPIGuardThreats struct {
	Guard  string `json:"guard"`
	Count  int    `json:"count"`
	Color  string `json:"color"`
}

// KPIStats is the full payload returned by GET /api/v1/stats/kpi.
type KPIStats struct {
	// Total event and incident counts (across the full stores).
	TotalEvents    int `json:"total_events"`
	TotalIncidents int `json:"total_incidents"`

	// Tier breakdown across all events in the EventStore.
	TierBreakdown []KPITierStat `json:"tier_breakdown"`

	// Risk score distribution across all events (four bands).
	RiskBreakdown []KPIRiskBand `json:"risk_breakdown"`

	// Incident status counts (pending / approved / denied / other).
	IncidentStatuses []KPIIncidentStatus `json:"incident_statuses"`

	// Threat counts per guard domain, derived from each domain's stats.
	GuardThreats []KPIGuardThreats `json:"guard_threats"`

	ComputedAt string `json:"computed_at"`
}

// handleKPIStats handles GET /api/v1/stats/kpi.
func (s *Server) handleKPIStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	// ── 1. Full EventStore sweep (up to 100 000) ──────────────────────────────
	allEvents, total := s.events.List(1, 100_000)

	tierCounts := map[string]int{"T0": 0, "T1": 0, "T2": 0, "T3": 0, "T4": 0}
	riskBands := [4]int{} // 0–25, 26–50, 51–75, 76–100

	// Domain threat counts.
	hostThreats := 0
	netThreats := 0
	commsThreats := 0
	agentThreats := 0
	modelBlocked := 0

	for _, ev := range allEvents {
		// Tier breakdown.
		tier, _ := ev["tier"].(string)
		if tier == "" {
			tier = "T0"
		}
		tierCounts[tier]++

		// Risk score bands.
		if rs, ok := ev["risk_score"].(float64); ok {
			switch {
			case rs <= 25:
				riskBands[0]++
			case rs <= 50:
				riskBands[1]++
			case rs <= 75:
				riskBands[2]++
			default:
				riskBands[3]++
			}
		}

		// Per-domain threat counting mirrors the logic in each domain handler.
		domain, _ := ev["domain"].(string)
		tierNum := parseTierNum(tier)
		rs, _ := ev["risk_score"].(float64)
		isThreat := tierNum >= 2 || rs >= 50

		switch domain {
		case "host":
			if isThreat {
				hostThreats++
			}
			// Network events are a subset of host events.
			if isNetworkEvent(ev) && isThreat {
				netThreats++
			}
		case "network":
			if isThreat {
				netThreats++
			}
		case "comms":
			// Mirror commsguard threat detection logic.
			if isThreat {
				commsThreats++
				break
			}
			evType := ""
			if meta, ok := ev["metadata"].(map[string]interface{}); ok {
				evType, _ = meta["event_type"].(string)
			}
			if evType == "" {
				evType, _ = ev["type"].(string)
			}
			if threatEventTypes[evType] {
				commsThreats++
			} else if indicators, ok := ev["indicators"].([]interface{}); ok && len(indicators) > 0 {
				commsThreats++
			}
		case "agent":
			if isThreat {
				agentThreats++
			}
		}
	}

	// ModelGuard blocked calls come from the in-process audit store.
	s.modelGuard.calls.mu.RLock()
	for _, entry := range s.modelGuard.calls.entries {
		if entry.Blocked {
			modelBlocked++
		}
	}
	s.modelGuard.calls.mu.RUnlock()

	// AgentGuard threats come from the agent registry (live counters are more
	// precise than event-store scanning for agent events).
	s.agentGuardStore.mu.RLock()
	for _, ag := range s.agentGuardStore.agents {
		agentThreats += ag.ThreatCount
	}
	s.agentGuardStore.mu.RUnlock()

	// ── 2. IncidentStore sweep ────────────────────────────────────────────────
	allIncidents, incTotal := s.incidents.List(1, 100_000)
	incStatuses := map[string]int{}
	for _, inc := range allIncidents {
		incStatuses[inc.Status]++
	}

	// ── 3. Assemble response ──────────────────────────────────────────────────
	tierOrder := []string{"T0", "T1", "T2", "T3", "T4"}
	tierBreakdown := make([]KPITierStat, 0, len(tierOrder))
	for _, t := range tierOrder {
		tierBreakdown = append(tierBreakdown, KPITierStat{Tier: t, Count: tierCounts[t]})
	}

	riskBreakdown := []KPIRiskBand{
		{Label: "0–25", Count: riskBands[0]},
		{Label: "26–50", Count: riskBands[1]},
		{Label: "51–75", Count: riskBands[2]},
		{Label: "76–100", Count: riskBands[3]},
	}

	statusOrder := []string{"pending", "approved", "denied", "overridden"}
	incidentStatuses := make([]KPIIncidentStatus, 0, len(statusOrder))
	for _, st := range statusOrder {
		incidentStatuses = append(incidentStatuses, KPIIncidentStatus{Status: st, Count: incStatuses[st]})
	}

	guardThreats := []KPIGuardThreats{
		{Guard: "HostGuard", Count: hostThreats, Color: "#ea580c"},
		{Guard: "AgentGuard", Count: agentThreats, Color: "#7c3aed"},
		{Guard: "CommsGuard", Count: commsThreats, Color: "#0891b2"},
		{Guard: "NetworkGuard", Count: netThreats, Color: "#22c55e"},
		{Guard: "ModelGuard", Count: modelBlocked, Color: "#2563eb"},
	}

	writeJSON(w, http.StatusOK, KPIStats{
		TotalEvents:      total,
		TotalIncidents:   incTotal,
		TierBreakdown:    tierBreakdown,
		RiskBreakdown:    riskBreakdown,
		IncidentStatuses: incidentStatuses,
		GuardThreats:     guardThreats,
		ComputedAt:       time.Now().UTC().Format(time.RFC3339),
	})
}
