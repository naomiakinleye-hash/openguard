// Package commsguardcommon provides shared types and utilities for the CommsGuard sensor.
package commsguardcommon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// knownCommsIndicators is the canonical set of CommsGuard threat indicators
// that the AI model is allowed to emit. Any value outside this set is discarded.
var knownCommsIndicators = map[string]bool{
	"phishing":               true,
	"credential_harvesting":  true,
	"data_exfiltration":      true,
	"social_engineering":     true,
	"suspicious_link":        true,
	"bulk_message":           true,
	"spam":                   true,
	"malware_attachment":     true,
	"cross_channel_attack":   true,
	"account_takeover_attempt": true,
}

// modelIntelRequest mirrors the model-gateway's modelRequest JSON schema.
type modelIntelRequest struct {
	EventID    string   `json:"event_id"`
	AgentID    string   `json:"agent_id"`
	Prompt     string   `json:"prompt"`
	RiskLevel  string   `json:"risk_level"`
	Domain     string   `json:"domain"`
	Indicators []string `json:"indicators"`
}

// modelIntelResponse mirrors the model-gateway's modelResponse JSON schema.
type modelIntelResponse struct {
	EventID string              `json:"event_id"`
	Result  *modelIntelResult   `json:"result,omitempty"`
	Error   string              `json:"error,omitempty"`
}

// modelIntelResult holds the fields from AnalysisResult that we care about.
type modelIntelResult struct {
	ProviderName string  `json:"provider_name"`
	Summary      string  `json:"summary"`
	Confidence   float64 `json:"confidence"`
	RiskLevel    string  `json:"risk_level"`
}

// aiThreatClassification is the JSON structure we instruct the model to return
// inside its summary. We parse it back out to extract canonical indicators.
type aiThreatClassification struct {
	Indicators []string `json:"indicators"`
	Confidence float64  `json:"confidence"`
	Rationale  string   `json:"rationale"`
}

// ModelIntelClient sends CommsEvents to the model-gateway agent for AI-powered
// threat enrichment using NATS request-reply semantics.
//
// The client is nil-safe — callers may pass a nil *ModelIntelClient and call
// Enrich; it will simply return nil without panicking.
//
// It is safe for concurrent use.
type ModelIntelClient struct {
	nc      *nats.Conn
	topic   string
	timeout time.Duration
	agentID string
	logger  *zap.Logger
}

// NewModelIntelClient creates a ModelIntelClient that dispatches AI enrichment
// requests to the model-gateway via NATS.
//
//   - nc      — shared NATS connection (caller owns lifecycle).
//   - topic   — NATS subject the model-gateway is subscribed to
//               (default: "openguard.modelguard.requests").
//   - timeout — per-request deadline (default: 10 s).
//   - agentID — identifies CommsGuard to the model-gateway rate-limiter
//               (default: "commsguard").
func NewModelIntelClient(nc *nats.Conn, topic string, timeout time.Duration, agentID string, logger *zap.Logger) *ModelIntelClient {
	if topic == "" {
		topic = "openguard.modelguard.requests"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if agentID == "" {
		agentID = "commsguard"
	}
	return &ModelIntelClient{
		nc:      nc,
		topic:   topic,
		timeout: timeout,
		agentID: agentID,
		logger:  logger,
	}
}

// Enrich sends the CommsEvent to the model-gateway for AI threat classification
// and returns any NEW indicators discovered by the model that are not already
// present in heuristicIndicators.
//
// Errors are handled gracefully: on timeout / unavailability the method returns
// nil so the caller falls back to heuristic-only results. This keeps CommsGuard
// functional when the model-gateway is not deployed.
func (m *ModelIntelClient) Enrich(ctx context.Context, event *CommsEvent, heuristicIndicators []string) []string {
	if m == nil || m.nc == nil {
		return nil
	}

	eventID := event.MessageID
	if eventID == "" {
		eventID = fmt.Sprintf("commsguard-%d", time.Now().UnixNano())
	}

	req := modelIntelRequest{
		EventID:    eventID,
		AgentID:    m.agentID,
		Prompt:     buildIntelPrompt(event, heuristicIndicators),
		RiskLevel:  inferRequestRiskLevel(heuristicIndicators),
		Domain:     "comms",
		Indicators: heuristicIndicators,
	}

	data, err := json.Marshal(req)
	if err != nil {
		m.logger.Warn("model-intel: failed to marshal request", zap.Error(err))
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	// nc.RequestWithContext sends to m.topic with a unique reply inbox and blocks
	// until the model-gateway publishes the result to that inbox.
	replyMsg, err := m.nc.RequestWithContext(reqCtx, m.topic, data)
	if err != nil {
		// The model-gateway may not be deployed; log at Debug to avoid noise.
		m.logger.Debug("model-intel: request failed (model-gateway unavailable?)",
			zap.String("channel", event.Channel),
			zap.String("event_id", eventID),
			zap.Error(err),
		)
		return nil
	}

	var resp modelIntelResponse
	if err := json.Unmarshal(replyMsg.Data, &resp); err != nil {
		m.logger.Warn("model-intel: failed to parse model-gateway response", zap.Error(err))
		return nil
	}
	if resp.Error != "" {
		m.logger.Debug("model-intel: model-gateway returned error",
			zap.String("event_id", eventID),
			zap.String("error", resp.Error),
		)
		return nil
	}
	if resp.Result == nil {
		return nil
	}

	novel := extractNovelIndicators(resp.Result.Summary, heuristicIndicators)
	if len(novel) > 0 {
		m.logger.Info("model-intel: AI enrichment added indicators",
			zap.String("channel", event.Channel),
			zap.String("event_id", eventID),
			zap.String("provider", resp.Result.ProviderName),
			zap.Float64("confidence", resp.Result.Confidence),
			zap.Strings("novel_indicators", novel),
		)
	}
	return novel
}

// buildIntelPrompt constructs a structured prompt instructing the model to return
// a JSON classification of the communication's threat level.
func buildIntelPrompt(event *CommsEvent, existing []string) string {
	var sb strings.Builder

	sb.WriteString("You are a communications security threat analyst.\n\n")
	sb.WriteString("Analyze the following message for security threats.\n\n")

	sb.WriteString("Channel: ")
	sb.WriteString(event.Channel)
	sb.WriteString("\nSender: ")
	if event.SenderID != "" {
		sb.WriteString(event.SenderID)
	} else {
		sb.WriteString("(unknown)")
	}

	if event.Content != "" {
		// Truncate to stay within a conservative token budget.
		c := event.Content
		if len(c) > 2000 {
			c = c[:2000] + "…"
		}
		sb.WriteString("\nMessage content:\n")
		sb.WriteString(c)
	}

	if len(existing) > 0 {
		sb.WriteString("\n\nHeuristic indicators already detected: ")
		sb.WriteString(strings.Join(existing, ", "))
	}

	sb.WriteString("\n\nRespond ONLY with a JSON object — no markdown fences, no prose:\n")
	sb.WriteString(`{"indicators":[],"confidence":0.0,"rationale":"..."}`)
	sb.WriteString("\n\nValid indicator values (use only these exact strings):\n")
	sb.WriteString("  phishing, credential_harvesting, data_exfiltration,\n")
	sb.WriteString("  social_engineering, suspicious_link, bulk_message, spam,\n")
	sb.WriteString("  malware_attachment, cross_channel_attack, account_takeover_attempt\n")
	sb.WriteString("\nReturn an empty indicators array if the message is benign.\n")
	sb.WriteString("Confidence must be a float in [0.0, 1.0].")

	return sb.String()
}

// inferRequestRiskLevel maps the heuristic indicator set to the model-gateway's
// risk_level field, which drives routing strategy (single / fallback / quorum).
func inferRequestRiskLevel(indicators []string) string {
	for _, ind := range indicators {
		switch ind {
		case "credential_harvesting", "data_exfiltration", "malware_attachment", "account_takeover_attempt":
			return "high"
		}
	}
	switch len(indicators) {
	case 0:
		return "low"
	case 1:
		return "medium"
	default:
		return "high"
	}
}

// extractNovelIndicators parses the AI summary JSON and returns only valid
// CommsGuard indicators that are not already present in heuristicIndicators.
func extractNovelIndicators(summary string, existing []string) []string {
	// The model should return raw JSON but may wrap it in prose; find the object.
	start := strings.Index(summary, "{")
	end := strings.LastIndex(summary, "}")
	if start < 0 || end < 0 || end <= start {
		return nil
	}

	var classified aiThreatClassification
	if err := json.Unmarshal([]byte(summary[start:end+1]), &classified); err != nil {
		return nil
	}

	existingSet := make(map[string]bool, len(existing))
	for _, ind := range existing {
		existingSet[strings.ToLower(ind)] = true
	}

	var novel []string
	for _, ind := range classified.Indicators {
		clean := strings.TrimSpace(strings.ToLower(ind))
		if knownCommsIndicators[clean] && !existingSet[clean] {
			novel = append(novel, clean)
		}
	}
	return novel
}
