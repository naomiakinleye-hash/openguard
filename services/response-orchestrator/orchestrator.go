// Package orchestrator implements the OpenGuard v5 response orchestrator.
// It coordinates detection → policy evaluation → tier-based response dispatch,
// human approval workflows, rollback, and audit trail emission.
package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	auditled "github.com/DiniMuhd7/openguard/services/audit-ledger"
	policyengine "github.com/DiniMuhd7/openguard/services/policy-engine"
)

// IncidentSink receives new incidents created by the orchestrator for persistence.
type IncidentSink interface {
	Add(incident *OrchestratorIncident)
}

// OrchestratorIncident is a minimal incident representation used by the orchestrator.
type OrchestratorIncident struct {
	ID          string  `json:"id"`
	EventID     string  `json:"event_id"`
	Type        string  `json:"type,omitempty"`
	Tier        int     `json:"tier,omitempty"`
	Status      string  `json:"status"`
	CreatedAt   string  `json:"created_at"`
	Description string  `json:"description,omitempty"`
	RiskScore   float64 `json:"risk_score,omitempty"`
}

// Config holds configuration for the Orchestrator.
type Config struct {
	// ApprovalTimeout is how long to wait for human approval before escalating.
	ApprovalTimeout time.Duration
	// IncidentSink receives new incidents when human approval is requested.
	IncidentSink IncidentSink
	// AlertWebhookURL is an optional incoming webhook URL (Slack, Teams, PagerDuty, etc.)
	// for T1+ alert dispatch. If empty, alerts are logged only.
	AlertWebhookURL string
}

// ApprovalRequest represents a pending human approval request.
type ApprovalRequest struct {
	// IncidentID is the incident requiring approval.
	IncidentID string
	// ProposedAction is the action awaiting approval.
	ProposedAction string
	// ResponseCh receives the operator's decision (true=approve, false=deny).
	ResponseCh chan bool
	// CreatedAt is when the approval request was created.
	CreatedAt time.Time
}

// Orchestrator coordinates the detection → policy → response pipeline.
type Orchestrator struct {
	cfg          Config
	policyEngine *policyengine.Engine
	ledger       *auditled.Ledger
	logger       *zap.Logger

	mu              sync.Mutex
	pendingApprovals map[string]*ApprovalRequest
}

// NewOrchestrator constructs a new Orchestrator.
func NewOrchestrator(cfg Config, pe *policyengine.Engine, ledger *auditled.Ledger, logger *zap.Logger) *Orchestrator {
	if cfg.ApprovalTimeout == 0 {
		cfg.ApprovalTimeout = 30 * time.Minute
	}
	return &Orchestrator{
		cfg:              cfg,
		policyEngine:     pe,
		ledger:           ledger,
		logger:           logger,
		pendingApprovals: make(map[string]*ApprovalRequest),
	}
}

// Dispatch processes a detected event through the policy engine and executes
// the tier-appropriate response. The proposedAction is automatically selected
// from the event's domain and tier when the caller passes an empty string.
func (o *Orchestrator) Dispatch(ctx context.Context, event map[string]interface{}, proposedAction string) error {
	eventID, _ := event["event_id"].(string)
	tier, _ := event["tier"].(string)

	// Auto-select a domain-appropriate proposed action when none is specified.
	if proposedAction == "" {
		proposedAction = selectAction(event)
	}

	// Extract the Layer 0 AI assessment the originating guard embedded in the
	// event's metadata. Passing it to Evaluate activates the constitutional
	// AI-first hierarchy; events without AI metadata fall through normally.
	ai := aiAssessmentFromEvent(event)
	decision := o.policyEngine.Evaluate(ctx, event, proposedAction, ai)

	// Audit the policy decision.
	entry := auditled.AuditEntry{
		EventID:         eventID,
		Actor:           "orchestrator",
		Action:          proposedAction,
		Decision:        string(decision.Decision),
		PolicyCitations: decision.PolicyCitations,
	}
	if err := o.ledger.Append(ctx, entry); err != nil {
		o.logger.Warn("orchestrator: audit append failed", zap.Error(err))
	}

	if decision.Decision == policyengine.DecisionDeny {
		o.logger.Info("orchestrator: action denied by policy",
			zap.String("event_id", eventID),
			zap.String("action", proposedAction),
			zap.Strings("citations", decision.PolicyCitations),
		)
		return nil
	}

	if decision.Decision == policyengine.DecisionRequireApproval {
		return o.requestApproval(ctx, eventID, proposedAction, tier)
	}

	// Policy allows — dispatch by tier.
	return o.dispatchByTier(ctx, eventID, tier, proposedAction)
}

// dispatchByTier executes the tier-appropriate response.
func (o *Orchestrator) dispatchByTier(ctx context.Context, eventID, tier, action string) error {
	switch tier {
	case "T0":
		o.logger.Info("orchestrator: T0 — log only", zap.String("event_id", eventID))

	case "T1":
		o.logger.Info("orchestrator: T1 — sending alert", zap.String("event_id", eventID))
		o.sendAlert(eventID, "on-call-channel")

	case "T2":
		o.logger.Info("orchestrator: T2 — requesting human approval", zap.String("event_id", eventID))
		return o.requestApproval(ctx, eventID, action, tier)

	case "T3":
		o.logger.Warn("orchestrator: T3 — executing containment", zap.String("event_id", eventID))
		o.executeContainment(ctx, eventID, action)

	case "T4":
		o.logger.Error("orchestrator: T4 — executing emergency lockdown", zap.String("event_id", eventID))
		o.executeEmergencyLockdown(ctx, eventID)

	default:
		o.logger.Warn("orchestrator: unknown tier, defaulting to T2 handling",
			zap.String("tier", tier), zap.String("event_id", eventID))
		return o.requestApproval(ctx, eventID, action, tier)
	}
	return nil
}

// requestApproval places an action on hold and waits for operator approval.
// If the timeout elapses without a response, the action is escalated.
func (o *Orchestrator) requestApproval(ctx context.Context, incidentID, proposedAction, tier string) error {
	ch := make(chan bool, 1)
	req := &ApprovalRequest{
		IncidentID:     incidentID,
		ProposedAction: proposedAction,
		ResponseCh:     ch,
		CreatedAt:      time.Now(),
	}

	o.mu.Lock()
	o.pendingApprovals[incidentID] = req
	o.mu.Unlock()

	// Notify the incident sink when approval is requested.
	if o.cfg.IncidentSink != nil {
		o.cfg.IncidentSink.Add(&OrchestratorIncident{
			ID:          incidentID,
			EventID:     incidentID,
			Type:        "approval_required",
			Status:      "pending",
			CreatedAt:   time.Now().UTC().Format(time.RFC3339),
			Description: proposedAction,
		})
	}

	o.logger.Info("orchestrator: approval requested",
		zap.String("incident_id", incidentID),
		zap.String("action", proposedAction),
		zap.Duration("timeout", o.cfg.ApprovalTimeout),
	)

	select {
	case approved := <-ch:
		o.mu.Lock()
		delete(o.pendingApprovals, incidentID)
		o.mu.Unlock()

		if approved {
			o.logger.Info("orchestrator: action approved by operator",
				zap.String("incident_id", incidentID))
			return o.dispatchByTier(ctx, incidentID, tier, proposedAction)
		}
		o.logger.Info("orchestrator: action denied by operator",
			zap.String("incident_id", incidentID))
		return nil

	case <-time.After(o.cfg.ApprovalTimeout):
		o.mu.Lock()
		delete(o.pendingApprovals, incidentID)
		o.mu.Unlock()
		o.logger.Warn("orchestrator: approval timed out — escalating",
			zap.String("incident_id", incidentID))
		// Escalate to T3 on timeout.
		return o.dispatchByTier(ctx, incidentID, "T3", proposedAction)

	case <-ctx.Done():
		return fmt.Errorf("orchestrator: approval cancelled: %w", ctx.Err())
	}
}

// Approve submits an operator approval for a pending incident.
func (o *Orchestrator) Approve(incidentID string) error {
	return o.respond(incidentID, true)
}

// Deny submits an operator denial for a pending incident.
func (o *Orchestrator) Deny(incidentID string) error {
	return o.respond(incidentID, false)
}

func (o *Orchestrator) respond(incidentID string, approved bool) error {
	o.mu.Lock()
	req, ok := o.pendingApprovals[incidentID]
	o.mu.Unlock()
	if !ok {
		return fmt.Errorf("orchestrator: no pending approval for incident %s", incidentID)
	}
	req.ResponseCh <- approved
	return nil
}

// sendAlert emits an alert notification for a T1+ event.
// If AlertWebhookURL is configured the alert is delivered as an HTTP POST
// (compatible with Slack incoming webhooks, Teams connectors, PagerDuty Events API v2, etc.).
// Falls back to structured logging when no webhook is configured.
func (o *Orchestrator) sendAlert(eventID, target string) {
	o.logger.Info("orchestrator: alert dispatched",
		zap.String("event_id", eventID),
		zap.String("target", target),
	)

	if o.cfg.AlertWebhookURL == "" {
		return
	}

	payload, err := json.Marshal(map[string]interface{}{
		"text":     fmt.Sprintf("[OpenGuard] Security alert — event %s requires attention on %s", eventID, target),
		"event_id": eventID,
		"target":   target,
		"ts":       time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		o.logger.Error("orchestrator: marshal alert payload failed", zap.Error(err))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.cfg.AlertWebhookURL, bytes.NewReader(payload))
	if err != nil {
		o.logger.Error("orchestrator: create alert request failed", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		o.logger.Error("orchestrator: alert webhook delivery failed", zap.Error(err))
		return
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode >= 300 {
		o.logger.Warn("orchestrator: alert webhook returned non-2xx",
			zap.Int("status", resp.StatusCode),
			zap.String("event_id", eventID),
		)
		return
	}
	o.logger.Info("orchestrator: alert webhook delivered", zap.String("event_id", eventID))
}

// executeContainment performs T3 containment actions.
func (o *Orchestrator) executeContainment(ctx context.Context, eventID, action string) {
	o.logger.Warn("orchestrator: containment executed",
		zap.String("event_id", eventID), zap.String("action", action))
	entry := auditled.AuditEntry{
		EventID:  eventID,
		Actor:    "orchestrator",
		Action:   "containment:" + action,
		Decision: "executed",
	}
	if err := o.ledger.Append(ctx, entry); err != nil {
		o.logger.Warn("orchestrator: audit append failed", zap.Error(err))
	}
	// Dispatch a T1 alert so the security team is notified of containment.
	o.sendAlert(eventID, "security-team")
}

// executeEmergencyLockdown performs T4 emergency lockdown.
func (o *Orchestrator) executeEmergencyLockdown(ctx context.Context, eventID string) {
	o.logger.Error("orchestrator: EMERGENCY LOCKDOWN", zap.String("event_id", eventID))
	entry := auditled.AuditEntry{
		EventID:  eventID,
		Actor:    "orchestrator",
		Action:   "emergency_lockdown",
		Decision: "executed",
	}
	if err := o.ledger.Append(ctx, entry); err != nil {
		o.logger.Warn("orchestrator: audit append failed", zap.Error(err))
	}
	o.sendAlert(eventID, "ciso")
}

// aiAssessmentFromEvent extracts the Layer 0 AI provider assessment embedded in
// the event's metadata by the originating guard. Returns nil when no AI metadata
// is present, allowing events that bypass model-gateway to fall through normally.
func aiAssessmentFromEvent(event map[string]interface{}) *policyengine.AIAssessment {
	meta, ok := event["metadata"].(map[string]interface{})
	if !ok {
		return nil
	}
	riskLevel, _ := meta["ai_risk_level"].(string)
	summary, _ := meta["ai_summary"].(string)
	provider, _ := meta["ai_provider"].(string)
	// All three fields absent means no AI enrichment was performed.
	if riskLevel == "" && summary == "" && provider == "" {
		return nil
	}
	confidence, _ := meta["ai_confidence"].(float64)
	action, _ := meta["ai_recommended_action"].(string)
	var indicators []string
	if raw, ok := meta["ai_indicators"]; ok {
		switch v := raw.(type) {
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					indicators = append(indicators, s)
				}
			}
		case []string:
			indicators = v
		}
	}
	return &policyengine.AIAssessment{
		RiskLevel:         riskLevel,
		Confidence:        confidence,
		Indicators:        indicators,
		Summary:           summary,
		RecommendedAction: action,
		ProviderName:      provider,
	}
}

// selectAction derives a domain-and-tier-appropriate proposed action from the event.
// This eliminates the need for callers to hard-code "auto_monitor" for every event
// and ensures that higher-severity events propose meaningful, domain-specific actions.
func selectAction(event map[string]interface{}) string {
	tier, _ := event["tier"].(string)
	domain, _ := event["domain"].(string)

	switch domain {
	case "comms":
		switch tier {
		case "T3", "T4":
			return "block_sender"
		case "T2":
			return "quarantine_message"
		case "T1":
			return "alert_security_team"
		}
	case "agent":
		switch tier {
		case "T3", "T4":
			return "suspend_agent"
		case "T2":
			return "quarantine_agent"
		case "T1":
			return "alert_security_team"
		}
	case "host":
		switch tier {
		case "T4":
			return "isolate_host"
		case "T3":
			return "contain_process"
		case "T2":
			return "contain_process"
		case "T1":
			return "alert_security_team"
		}
	case "model":
		switch tier {
		case "T3", "T4":
			return "block_model_request"
		case "T2":
			return "quarantine_model_output"
		case "T1":
			return "alert_security_team"
		}
	case "network":
		switch tier {
		case "T3", "T4":
			return "block_network_flow"
		case "T2":
			return "quarantine_host"
		case "T1":
			return "alert_security_team"
		}
	}
	return "auto_monitor"
}
