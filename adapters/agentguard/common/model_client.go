// Package agentguardcommon provides shared types and utilities for the AgentGuard sensor.
package agentguardcommon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// knownAgentIndicators is the canonical set of AgentGuard threat indicators the
// AI model is allowed to emit. Values outside this set are discarded to prevent
// prompt-injection attacks from injecting arbitrary indicators.
var knownAgentIndicators = map[string]bool{
	"prompt_injection":            true,
	"data_exfiltration_attempt":   true,
	"unsanctioned_outreach":       true,
	"unapproved_tool_use":         true,
	"self_policy_modification":    true,
	"quota_exceeded":              true,
	"unauthorized_domain_access":  true,
	"suspicious_tool_chain":       true,
	"rate_limit_evasion":          true,
	"credential_exfiltration":     true,
	"jailbreak_attempt":           true,
	"adversarial_prompt":          true,
	"indirect_prompt_injection":   true,
	"multi_step_attack":           true,
	"supply_chain_compromise":     true,
}

// agentModelIntelRequest mirrors the model-gateway's modelRequest JSON schema.
type agentModelIntelRequest struct {
	EventID    string   `json:"event_id"`
	AgentID    string   `json:"agent_id"`
	Prompt     string   `json:"prompt"`
	RiskLevel  string   `json:"risk_level"`
	Domain     string   `json:"domain"`
	Indicators []string `json:"indicators"`
}

// agentModelIntelResponse mirrors the model-gateway's modelResponse JSON schema.
type agentModelIntelResponse struct {
	EventID string                  `json:"event_id"`
	Result  *agentModelIntelResult  `json:"result,omitempty"`
	Error   string                  `json:"error,omitempty"`
}

// agentModelIntelResult holds the fields from AnalysisResult that we use.
type agentModelIntelResult struct {
	ProviderName string  `json:"provider_name"`
	Summary      string  `json:"summary"`
	Confidence   float64 `json:"confidence"`
	RiskLevel    string  `json:"risk_level"`
}

// agentAIClassification is the JSON structure the model should return in its
// summary. We parse it back to extract canonical indicators.
type agentAIClassification struct {
	Indicators []string `json:"indicators"`
	Confidence float64  `json:"confidence"`
	Rationale  string   `json:"rationale"`
}

// AgentModelIntelClient sends ActionRequests and AgentEvents to the
// model-gateway agent for AI-powered threat enrichment via NATS request-reply.
//
// The client is nil-safe — callers may pass a nil *AgentModelIntelClient and
// call Enrich; it will simply return nil without panicking.
//
// It is safe for concurrent use.
type AgentModelIntelClient struct {
	nc      *nats.Conn
	topic   string
	timeout time.Duration
	agentID string
	logger  *zap.Logger
}

// NewAgentModelIntelClient creates an AgentModelIntelClient that dispatches AI
// enrichment requests to the model-gateway via NATS.
//
//   - nc      — shared NATS connection (caller owns lifecycle).
//   - topic   — NATS subject the model-gateway is subscribed to
//               (default: "openguard.modelguard.requests").
//   - timeout — per-request deadline (default: 10 s).
//   - agentID — identifies AgentGuard to the model-gateway rate-limiter
//               (default: "agentguard").
func NewAgentModelIntelClient(nc *nats.Conn, topic string, timeout time.Duration, agentID string, logger *zap.Logger) *AgentModelIntelClient {
	if topic == "" {
		topic = "openguard.modelguard.requests"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if agentID == "" {
		agentID = "agentguard"
	}
	return &AgentModelIntelClient{
		nc:      nc,
		topic:   topic,
		timeout: timeout,
		agentID: agentID,
		logger:  logger,
	}
}

// Enrich sends the action request context to the model-gateway for AI threat
// classification and returns any NEW indicators not already in existingIndicators.
//
// Errors are handled gracefully: on timeout or unavailability the method returns
// nil so the caller falls back to heuristic-only results.
func (m *AgentModelIntelClient) Enrich(ctx context.Context, req *ActionRequest, profile *AgentProfile, existingIndicators []string) []string {
	if m == nil || m.nc == nil {
		return nil
	}

	eventID := fmt.Sprintf("agentguard-%d", time.Now().UnixNano())

	modelReq := agentModelIntelRequest{
		EventID:    eventID,
		AgentID:    m.agentID,
		Prompt:     buildAgentIntelPrompt(req, profile, existingIndicators),
		RiskLevel:  inferAgentRiskLevel(existingIndicators),
		Domain:     "agent",
		Indicators: existingIndicators,
	}

	data, err := json.Marshal(modelReq)
	if err != nil {
		m.logger.Warn("agent-model-intel: marshal request failed", zap.Error(err))
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	replyMsg, err := m.nc.RequestWithContext(reqCtx, m.topic, data)
	if err != nil {
		// Model-gateway may not be deployed; log at Debug to avoid noise.
		m.logger.Debug("agent-model-intel: request failed (model-gateway unavailable?)",
			zap.String("action_type", req.ActionType),
			zap.String("agent_id", req.AgentID),
			zap.String("event_id", eventID),
			zap.Error(err),
		)
		return nil
	}

	var resp agentModelIntelResponse
	if err := json.Unmarshal(replyMsg.Data, &resp); err != nil {
		m.logger.Warn("agent-model-intel: parse response failed", zap.Error(err))
		return nil
	}
	if resp.Error != "" {
		m.logger.Debug("agent-model-intel: model-gateway returned error",
			zap.String("event_id", eventID),
			zap.String("error", resp.Error),
		)
		return nil
	}
	if resp.Result == nil {
		return nil
	}

	novel := extractNovelAgentIndicators(resp.Result.Summary, existingIndicators)
	if len(novel) > 0 {
		m.logger.Info("agent-model-intel: AI enrichment added indicators",
			zap.String("action_type", req.ActionType),
			zap.String("agent_id", req.AgentID),
			zap.String("provider", resp.Result.ProviderName),
			zap.Float64("confidence", resp.Result.Confidence),
			zap.Strings("novel_indicators", novel),
		)
	}
	return novel
}

// buildAgentIntelPrompt constructs a structured prompt for AI threat classification
// of an agent action request.
func buildAgentIntelPrompt(req *ActionRequest, profile *AgentProfile, existing []string) string {
	var sb strings.Builder

	sb.WriteString("You are an AI agent security analyst specialising in detecting malicious AI agent behaviour.\n\n")
	sb.WriteString("Analyze the following AI agent action for threats, prompt injection, and policy violations.\n\n")

	sb.WriteString(fmt.Sprintf("Agent ID: %s\n", req.AgentID))
	if profile != nil {
		sb.WriteString(fmt.Sprintf("Agent Type: %s\n", profile.AgentType))
		sb.WriteString(fmt.Sprintf("Approved Tools: %s\n", strings.Join(profile.ApprovedTools, ", ")))
		sb.WriteString(fmt.Sprintf("Approved Domains: %s\n", strings.Join(profile.ApprovedDomains, ", ")))
	}
	sb.WriteString(fmt.Sprintf("Action Type: %s\n", req.ActionType))
	if req.ToolName != "" {
		sb.WriteString(fmt.Sprintf("Tool: %s\n", req.ToolName))
	}
	if req.TargetDomain != "" {
		sb.WriteString(fmt.Sprintf("Target Domain: %s\n", req.TargetDomain))
	}
	if req.TargetResource != "" {
		sb.WriteString(fmt.Sprintf("Target Resource: %s\n", req.TargetResource))
	}

	if len(existing) > 0 {
		sb.WriteString("Already detected indicators: " + strings.Join(existing, ", ") + "\n")
	}

	sb.WriteString("\nValid indicators you may emit (ONLY choose from this list): ")
	sb.WriteString("prompt_injection, data_exfiltration_attempt, unsanctioned_outreach, unapproved_tool_use, ")
	sb.WriteString("self_policy_modification, quota_exceeded, unauthorized_domain_access, suspicious_tool_chain, ")
	sb.WriteString("rate_limit_evasion, credential_exfiltration, jailbreak_attempt, adversarial_prompt, ")
	sb.WriteString("indirect_prompt_injection, multi_step_attack, supply_chain_compromise.\n\n")
	sb.WriteString("Respond ONLY with valid JSON (no prose): " +
		`{"indicators":["..."],"confidence":0.0,"rationale":"..."}`)

	return sb.String()
}

// inferAgentRiskLevel maps existing indicators to a risk level for model-gateway
// request prioritisation.
func inferAgentRiskLevel(indicators []string) string {
	criticalSet := map[string]bool{
		"prompt_injection": true, "self_policy_modification": true,
		"jailbreak_attempt": true, "adversarial_prompt": true,
		"indirect_prompt_injection": true, "supply_chain_compromise": true,
	}
	highSet := map[string]bool{
		"data_exfiltration_attempt": true, "credential_exfiltration": true,
		"multi_step_attack": true, "unsanctioned_outreach": true,
	}
	for _, ind := range indicators {
		if criticalSet[ind] {
			return "critical"
		}
	}
	for _, ind := range indicators {
		if highSet[ind] {
			return "high"
		}
	}
	if len(indicators) > 0 {
		return "medium"
	}
	return "low"
}

// extractNovelAgentIndicators parses the model's JSON summary and returns
// indicators that are valid (in knownAgentIndicators) and not already in existing.
func extractNovelAgentIndicators(summary string, existing []string) []string {
	existingSet := make(map[string]bool, len(existing))
	for _, i := range existing {
		existingSet[i] = true
	}

	start := strings.Index(summary, "{")
	end := strings.LastIndex(summary, "}")
	if start == -1 || end <= start {
		return nil
	}
	snippet := summary[start : end+1]

	var classification agentAIClassification
	if err := json.Unmarshal([]byte(snippet), &classification); err != nil {
		return nil
	}

	var novel []string
	for _, ind := range classification.Indicators {
		ind = strings.TrimSpace(strings.ToLower(ind))
		if knownAgentIndicators[ind] && !existingSet[ind] {
			novel = append(novel, ind)
		}
	}
	return novel
}
