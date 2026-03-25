// Package agentguardcommon provides shared types and utilities for the AgentGuard sensor.
package agentguardcommon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// AgentEvent is the raw agent sensor event before normalization.
type AgentEvent struct {
	// EventType describes the category of agent activity.
	// One of: agent_action_submitted, unsanctioned_outreach, unapproved_tool_use,
	// direct_channel_access, policy_modification_attempt, agent_suspended,
	// agent_quarantined, resource_quota_exceeded, prompt_injection_detected,
	// data_exfiltration_attempt, multi_condition_violation.
	EventType string
	// AgentID is the unique ID of the AI agent.
	AgentID string
	// AgentName is the human-readable name of the agent.
	AgentName string
	// AgentType is the agent category (e.g. "llm_assistant", "automation_bot", "code_agent").
	AgentType string
	// ActionType is the action the agent attempted.
	ActionType string
	// ToolName is the tool name if the action is a tool call.
	ToolName string
	// TargetDomain is the domain for outbound requests.
	TargetDomain string
	// TargetResource is the resource or path targeted by the action.
	TargetResource string
	// PolicyMatch is the policy evaluation result: "allow", "deny", or "none".
	PolicyMatch string
	// ConditionsMatched is the number of violation conditions matched.
	ConditionsMatched int
	// Timestamp is when the event occurred.
	Timestamp time.Time
	// Indicators is the list of matched violation indicator strings.
	Indicators []string
	// RawData holds arbitrary additional data for the event.
	RawData map[string]interface{}
}

// ToUnifiedEvent converts an AgentEvent to the UnifiedEvent JSON format
// compatible with the ingest service schema (schemas/unified-event.schema.json).
// It generates a UUID event_id, computes a SHA-256 audit_hash, and sets
// domain="agent", human_approved=false.
func (e *AgentEvent) ToUnifiedEvent() ([]byte, error) {
	severity, riskScore, tier := classifyEvent(e)

	targetID := e.TargetResource
	if targetID == "" {
		targetID = e.TargetDomain
	}

	metadata := map[string]interface{}{
		"agent_id":           e.AgentID,
		"agent_name":         e.AgentName,
		"agent_type":         e.AgentType,
		"action_type":        e.ActionType,
		"tool_name":          e.ToolName,
		"target_domain":      e.TargetDomain,
		"target_resource":    e.TargetResource,
		"policy_match":       e.PolicyMatch,
		"conditions_matched": e.ConditionsMatched,
		"event_type":         e.EventType,
	}
	for k, v := range e.RawData {
		metadata[k] = v
	}

	indicators := e.Indicators
	if indicators == nil {
		indicators = []string{}
	}

	intermediate := map[string]interface{}{
		"event_id":  uuid.New().String(),
		"timestamp": e.Timestamp.UTC().Format(time.RFC3339),
		"source": map[string]interface{}{
			"type":     "agent",
			"adapter":  "agentguard",
			"agent_id": e.AgentID,
		},
		"domain":     "agent",
		"severity":   severity,
		"risk_score": riskScore,
		"tier":       tier,
		"actor": map[string]interface{}{
			"id":   e.AgentID,
			"type": "agent",
		},
		"target": map[string]interface{}{
			"id":   targetID,
			"type": "resource",
		},
		"indicators":       indicators,
		"policy_citations": []string{},
		"human_approved":   false,
		"audit_hash":       "",
		"metadata":         metadata,
	}

	// First marshal without audit_hash to compute hash.
	intermediate["audit_hash"] = ""
	partial, err := json.Marshal(intermediate)
	if err != nil {
		return nil, fmt.Errorf("agentguard: marshal partial event: %w", err)
	}

	hash := sha256.Sum256(partial)
	intermediate["audit_hash"] = fmt.Sprintf("%x", hash)

	payload, err := json.Marshal(intermediate)
	if err != nil {
		return nil, fmt.Errorf("agentguard: marshal unified event: %w", err)
	}
	return payload, nil
}

// classifyEvent assigns severity, risk_score, and tier based on indicators and event type.
// Tier boundaries follow the detect service: T0=0–19, T1=20–39, T2=40–59, T3=60–79, T4=80–100.
func classifyEvent(e *AgentEvent) (severity string, riskScore float64, tier string) {
	// Indicator special-cases take priority over event type.
	for _, ind := range e.Indicators {
		switch ind {
		case "self_policy_modification":
			return "critical", 95.0, "immediate"
		case "prompt_injection":
			return "critical", 90.0, "immediate"
		case "data_exfiltration":
			return "critical", 92.0, "immediate"
		}
	}
	switch e.EventType {
	case "agent_action_submitted":
		return "info", 5.0, "T0"
	case "unsanctioned_outreach":
		return "high", 70.0, "T2"
	case "unapproved_tool_use":
		return "high", 70.0, "T2"
	case "direct_channel_access":
		return "high", 75.0, "T3"
	case "policy_modification_attempt":
		return "critical", 95.0, "immediate"
	case "agent_suspended":
		return "high", 65.0, "T2"
	case "agent_quarantined":
		return "critical", 85.0, "T3"
	case "resource_quota_exceeded":
		return "medium", 40.0, "T1"
	case "prompt_injection_detected":
		return "critical", 90.0, "immediate"
	case "data_exfiltration_attempt":
		return "critical", 92.0, "immediate"
	case "multi_condition_violation":
		return "critical", 95.0, "immediate"
	default:
		return "medium", 40.0, "T1"
	}
}
