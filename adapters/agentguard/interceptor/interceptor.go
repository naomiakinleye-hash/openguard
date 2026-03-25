// Package agentguardinterceptor provides the HTTP handler that intercepts agent
// action submissions, evaluates them against policy, and emits AgentEvents.
package agentguardinterceptor

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/agentguard/common"
	"go.uber.org/zap"
)

// AgentInterceptor handles HTTP requests for agent action interception and management.
type AgentInterceptor struct {
	registry    *common.AgentRegistry
	publisher   *common.Publisher
	checker     *common.PolicyComplianceChecker
	modelClient *common.AgentModelIntelClient
	logger      *zap.Logger
}

// NewAgentInterceptor creates a new AgentInterceptor.
func NewAgentInterceptor(
	registry *common.AgentRegistry,
	publisher *common.Publisher,
	checker *common.PolicyComplianceChecker,
	logger *zap.Logger,
) *AgentInterceptor {
	return &AgentInterceptor{
		registry:  registry,
		publisher: publisher,
		checker:   checker,
		logger:    logger,
	}
}

// WithModelIntelClient attaches an AI enrichment client to the interceptor.
func (i *AgentInterceptor) WithModelIntelClient(client *common.AgentModelIntelClient) *AgentInterceptor {
	i.modelClient = client
	return i
}

// RegisterRoutes registers all AgentInterceptor routes onto the given mux.
func (i *AgentInterceptor) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/agent/action", i.handleAction)
	mux.HandleFunc("/agent/register", i.handleRegister)
	mux.HandleFunc("/agent/list", i.handleList)
	mux.HandleFunc("/agent/status/", i.handleStatus)
	mux.HandleFunc("/agent/unsuspend/", i.handleUnsuspend)
}

// handleAction handles POST /agent/action — evaluates a submitted agent action.
func (i *AgentInterceptor) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req common.ActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	profile, ok := i.registry.Get(req.AgentID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not registered"})
		return
	}

	ctx := r.Context()

	// Always emit a baseline submission event.
	baseEvent := &common.AgentEvent{
		EventType:      "agent_action_submitted",
		AgentID:        req.AgentID,
		AgentName:      profile.AgentName,
		AgentType:      profile.AgentType,
		ActionType:     req.ActionType,
		ToolName:       req.ToolName,
		TargetDomain:   req.TargetDomain,
		TargetResource: req.TargetResource,
		PolicyMatch:    "none",
		Timestamp:      time.Now(),
		Indicators:     []string{},
	}
	i.publishEvent(ctx, baseEvent)

	result := i.checker.Check(profile, &req)

	// Stage 2: AI enrichment — if violations exist, forward action context to
	// the model-gateway for semantic threat classification. Novel indicators are
	// merged before the violation event is emitted.
	var aiIndicators []string
	if i.modelClient != nil && len(result.Violations) > 0 {
		aiIndicators = i.modelClient.Enrich(ctx, &req, profile, result.Violations)
	}

	if len(result.Violations) == 0 {
		baseEvent.PolicyMatch = "allow"
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"allowed":     true,
			"agent_id":    req.AgentID,
			"action_type": req.ActionType,
		})
		return
	}

	// Emit violation-specific event.
	violationEventType := pickViolationEventType(result.Violations)
	allViolationIndicators := append(result.Violations, aiIndicators...)
	violationEvent := &common.AgentEvent{
		EventType:         violationEventType,
		AgentID:           req.AgentID,
		AgentName:         profile.AgentName,
		AgentType:         profile.AgentType,
		ActionType:        req.ActionType,
		ToolName:          req.ToolName,
		TargetDomain:      req.TargetDomain,
		TargetResource:    req.TargetResource,
		PolicyMatch:       "deny",
		ConditionsMatched: result.ConditionsCount,
		Timestamp:         time.Now(),
		Indicators:        allViolationIndicators,
	}
	i.publishEvent(ctx, violationEvent)

	// Suspend if required.
	if result.ShouldSuspend {
		i.registry.Suspend(req.AgentID)
		i.publishEvent(ctx, &common.AgentEvent{
			EventType:      "agent_suspended",
			AgentID:        req.AgentID,
			AgentName:      profile.AgentName,
			AgentType:      profile.AgentType,
			ActionType:     req.ActionType,
			PolicyMatch:    "deny",
			Timestamp:      time.Now(),
			Indicators:     result.Violations,
		})
	}

	// Quarantine on self-policy modification.
	if containsViolation(result.Violations, "self_policy_modification") {
		i.registry.Quarantine(req.AgentID)
		i.publishEvent(ctx, &common.AgentEvent{
			EventType:      "agent_quarantined",
			AgentID:        req.AgentID,
			AgentName:      profile.AgentName,
			AgentType:      profile.AgentType,
			ActionType:     req.ActionType,
			PolicyMatch:    "deny",
			Timestamp:      time.Now(),
			Indicators:     result.Violations,
		})
	}

	// Multi-condition violation escalation.
	if result.ConditionsCount >= 3 {
		i.publishEvent(ctx, &common.AgentEvent{
			EventType:         "multi_condition_violation",
			AgentID:           req.AgentID,
			AgentName:         profile.AgentName,
			AgentType:         profile.AgentType,
			ActionType:        req.ActionType,
			PolicyMatch:       "deny",
			ConditionsMatched: result.ConditionsCount,
			Timestamp:         time.Now(),
			Indicators:        result.Violations,
		})
	}

	writeJSON(w, http.StatusForbidden, map[string]interface{}{
		"blocked":    true,
		"violations": result.Violations,
		"message":    "action blocked by AgentGuard policy",
	})
}

// handleRegister handles POST /agent/register — registers a new agent profile.
func (i *AgentInterceptor) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var profile common.AgentProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if profile.AgentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_id is required"})
		return
	}

	i.registry.Register(&profile)
	i.logger.Info("agentguard: registered agent",
		zap.String("agent_id", profile.AgentID),
		zap.String("agent_name", profile.AgentName),
	)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"registered": true,
		"agent_id":   profile.AgentID,
	})
}

// handleStatus handles GET /agent/status/{agent_id} — returns agent profile info.
func (i *AgentInterceptor) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	agentID := strings.TrimPrefix(r.URL.Path, "/agent/status/")
	if agentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_id is required"})
		return
	}

	profile, ok := i.registry.Get(agentID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not registered"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent_id":         profile.AgentID,
		"agent_name":       profile.AgentName,
		"agent_type":       profile.AgentType,
		"approved_tools":   profile.ApprovedTools,
		"approved_domains": profile.ApprovedDomains,
		"suspended":        profile.Suspended,
		"quarantined":      profile.Quarantined,
	})
}

// handleUnsuspend handles POST /agent/unsuspend/{agent_id} — un-suspends an agent.
func (i *AgentInterceptor) handleUnsuspend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	agentID := strings.TrimPrefix(r.URL.Path, "/agent/unsuspend/")
	if agentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent_id is required"})
		return
	}

	profile, ok := i.registry.Get(agentID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not registered"})
		return
	}

	_ = profile // profile validated; unsuspend via registry to hold write lock
	i.registry.Unsuspend(agentID)
	i.logger.Info("agentguard: agent unsuspended by operator",
		zap.String("agent_id", agentID),
	)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"unsuspended": true,
		"agent_id":    agentID,
	})
}

// handleList handles GET /agent/list — lists all registered agents.
func (i *AgentInterceptor) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	profiles := i.registry.List()
	type agentSummary struct {
		AgentID     string `json:"agent_id"`
		AgentName   string `json:"agent_name"`
		AgentType   string `json:"agent_type"`
		Suspended   bool   `json:"suspended"`
		Quarantined bool   `json:"quarantined"`
	}
	summaries := make([]agentSummary, 0, len(profiles))
	for _, p := range profiles {
		summaries = append(summaries, agentSummary{
			AgentID:     p.AgentID,
			AgentName:   p.AgentName,
			AgentType:   p.AgentType,
			Suspended:   p.Suspended,
			Quarantined: p.Quarantined,
		})
	}
	writeJSON(w, http.StatusOK, summaries)
}

// publishEvent publishes an AgentEvent, logging a warning on failure.
func (i *AgentInterceptor) publishEvent(ctx context.Context, event *common.AgentEvent) {
	if err := i.publisher.Publish(ctx, event); err != nil {
		i.logger.Warn("agentguard: failed to publish event",
			zap.String("event_type", event.EventType),
			zap.String("agent_id", event.AgentID),
			zap.Error(err),
		)
	}
}

// pickViolationEventType returns the most severe event type for the given violations.
func pickViolationEventType(violations []string) string {
	// Priority order: critical violations first.
	priority := []struct {
		indicator string
		eventType string
	}{
		{"self_policy_modification", "policy_modification_attempt"},
		{"prompt_injection", "prompt_injection_detected"},
		{"data_exfiltration", "data_exfiltration_attempt"},
		{"agent_quarantined", "agent_quarantined"},
		{"direct_channel_access", "direct_channel_access"},
		{"unsanctioned_outreach", "unsanctioned_outreach"},
		{"unapproved_tool_use", "unapproved_tool_use"},
		{"agent_suspended", "agent_suspended"},
	}
	for _, p := range priority {
		if containsViolation(violations, p.indicator) {
			return p.eventType
		}
	}
	return "unsanctioned_outreach"
}

// containsViolation returns true if target is in the violations slice.
func containsViolation(violations []string, target string) bool {
	for _, v := range violations {
		if v == target {
			return true
		}
	}
	return false
}

// writeJSON encodes v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
