// Package networkguardcommon provides shared types and utilities for the NetworkGuard sensor.
package networkguardcommon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// knownNetworkIndicators is the canonical set of NetworkGuard threat indicators
// the AI model is allowed to emit. Values outside this set are discarded.
var knownNetworkIndicators = map[string]bool{
	"port_scan":                 true,
	"c2_beaconing":              true,
	"lateral_movement":          true,
	"dns_tunneling":             true,
	"data_exfiltration":         true,
	"protocol_anomaly":          true,
	"geo_ip_anomaly":            true,
	"remote_access_anomaly":     true,
	"network_reconnaissance":    true,
	"suspicious_dns_query":      true,
	"connection_flood":          true,
	"unauthorized_service":      true,
	"encrypted_c2":              true,
	"domain_generation_algo":    true,
	"low_and_slow_exfiltration": true,
}

// networkModelIntelRequest mirrors the model-gateway's modelRequest JSON schema.
type networkModelIntelRequest struct {
	EventID    string   `json:"event_id"`
	AgentID    string   `json:"agent_id"`
	Prompt     string   `json:"prompt"`
	RiskLevel  string   `json:"risk_level"`
	Domain     string   `json:"domain"`
	Indicators []string `json:"indicators"`
}

// networkModelIntelResponse mirrors the model-gateway's modelResponse JSON schema.
type networkModelIntelResponse struct {
	EventID string                    `json:"event_id"`
	Result  *networkModelIntelResult  `json:"result,omitempty"`
	Error   string                    `json:"error,omitempty"`
}

// networkModelIntelResult holds the fields from AnalysisResult that we use.
type networkModelIntelResult struct {
	ProviderName string  `json:"provider_name"`
	Summary      string  `json:"summary"`
	Confidence   float64 `json:"confidence"`
	RiskLevel    string  `json:"risk_level"`
}

// networkAIClassification is the JSON structure the model should return.
type networkAIClassification struct {
	Indicators []string `json:"indicators"`
	Confidence float64  `json:"confidence"`
	Rationale  string   `json:"rationale"`
}

// NetworkModelIntelClient sends network events to the model-gateway agent for
// AI-powered threat enrichment using NATS request-reply semantics.
//
// The client is nil-safe — callers may pass a nil *NetworkModelIntelClient and
// call Enrich; it will simply return nil without panicking.
//
// It is safe for concurrent use.
type NetworkModelIntelClient struct {
	nc      *nats.Conn
	topic   string
	timeout time.Duration
	agentID string
	logger  *zap.Logger
}

// NewNetworkModelIntelClient creates a NetworkModelIntelClient that dispatches
// AI enrichment requests to the model-gateway via NATS.
func NewNetworkModelIntelClient(nc *nats.Conn, topic string, timeout time.Duration, agentID string, logger *zap.Logger) *NetworkModelIntelClient {
	if topic == "" {
		topic = "openguard.modelguard.requests"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if agentID == "" {
		agentID = "networkguard"
	}
	return &NetworkModelIntelClient{
		nc:      nc,
		topic:   topic,
		timeout: timeout,
		agentID: agentID,
		logger:  logger,
	}
}

// NetworkModelAssessment contains the full AI provider response for a NetworkGuard event.
// It is embedded into the unified event's metadata so the orchestrator can build
// a policyengine.AIAssessment for Layer 0 constitutional evaluation without an
// additional model call.
type NetworkModelAssessment struct {
	RiskLevel         string
	Confidence        float64
	Summary           string
	ProviderName      string
	RecommendedAction string
	Indicators        []string
}

// recommendedNetworkAction derives the constitutional recommended action from the
// model's risk level output.
func recommendedNetworkAction(riskLevel string) string {
	switch strings.ToLower(riskLevel) {
	case "critical", "high":
		return "block"
	case "medium":
		return "escalate"
	default:
		return "allow"
	}
}

// Enrich sends the network event context to the model-gateway for AI threat
// classification and returns any NEW indicators not already in existingIndicators
// plus the full assessment for Layer 0 constitutional evaluation.
//
// Errors are handled gracefully: on timeout or unavailability the method returns
// nil so the caller falls back to heuristic-only results.
func (m *NetworkModelIntelClient) Enrich(ctx context.Context, event map[string]interface{}, existingIndicators []string) ([]string, *NetworkModelAssessment) {
	if m == nil || m.nc == nil {
		return nil, nil
	}

	eventID, _ := event["event_id"].(string)
	if eventID == "" {
		eventID = fmt.Sprintf("networkguard-%d", time.Now().UnixNano())
	}

	req := networkModelIntelRequest{
		EventID:    eventID,
		AgentID:    m.agentID,
		Prompt:     buildNetworkIntelPrompt(event, existingIndicators),
		RiskLevel:  inferNetworkRiskLevel(existingIndicators),
		Domain:     "network",
		Indicators: existingIndicators,
	}

	data, err := json.Marshal(req)
	if err != nil {
		m.logger.Warn("network-model-intel: marshal request failed", zap.Error(err))
		return nil, nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	replyMsg, err := m.nc.RequestWithContext(reqCtx, m.topic, data)
	if err != nil {
		m.logger.Debug("network-model-intel: request failed (model-gateway unavailable?)",
			zap.String("event_id", eventID),
			zap.Error(err),
		)
		return nil, nil
	}

	var resp networkModelIntelResponse
	if err := json.Unmarshal(replyMsg.Data, &resp); err != nil {
		m.logger.Warn("network-model-intel: parse response failed", zap.Error(err))
		return nil, nil
	}
	if resp.Error != "" || resp.Result == nil {
		return nil, nil
	}

	novel := extractNovelNetworkIndicators(resp.Result.Summary, existingIndicators)
	assessment := &NetworkModelAssessment{
		RiskLevel:         resp.Result.RiskLevel,
		Confidence:        resp.Result.Confidence,
		Summary:           resp.Result.Summary,
		ProviderName:      resp.Result.ProviderName,
		RecommendedAction: recommendedNetworkAction(resp.Result.RiskLevel),
		Indicators:        novel,
	}
	if len(novel) > 0 {
		m.logger.Info("network-model-intel: AI enrichment added indicators",
			zap.String("event_id", eventID),
			zap.String("provider", resp.Result.ProviderName),
			zap.Float64("confidence", resp.Result.Confidence),
			zap.Strings("novel_indicators", novel),
		)
	}
	return novel, assessment
}

// buildNetworkIntelPrompt constructs a structured prompt for network threat analysis.
func buildNetworkIntelPrompt(event map[string]interface{}, existing []string) string {
	var sb strings.Builder

	sb.WriteString("You are a network security threat analyst.\n\n")
	sb.WriteString("Analyze the following network event for advanced threats: C2 beaconing, lateral movement, ")
	sb.WriteString("DNS tunneling, data exfiltration, port scans, and protocol anomalies.\n\n")

	if meta, ok := event["metadata"].(map[string]interface{}); ok {
		if et, _ := meta["event_type"].(string); et != "" {
			sb.WriteString("Event Type: " + et + "\n")
		}
		if proto, _ := meta["protocol"].(string); proto != "" {
			sb.WriteString("Protocol: " + proto + "\n")
		}
		if remoteAddr, _ := meta["remote_addr"].(string); remoteAddr != "" {
			sb.WriteString("Remote Address: " + remoteAddr + "\n")
		}
		if remotePort, ok := meta["remote_port"]; ok {
			sb.WriteString(fmt.Sprintf("Remote Port: %v\n", remotePort))
		}
		if dnsQuery, _ := meta["dns_query_name"].(string); dnsQuery != "" {
			sb.WriteString("DNS Query: " + dnsQuery + "\n")
		}
	}

	if src, ok := event["source"].(map[string]interface{}); ok {
		if hostID, _ := src["host_id"].(string); hostID != "" {
			sb.WriteString("Source Host: " + hostID + "\n")
		}
	}

	if tier, _ := event["tier"].(string); tier != "" {
		sb.WriteString("Current Tier: " + tier + "\n")
	}

	if len(existing) > 0 {
		sb.WriteString("Already detected indicators: " + strings.Join(existing, ", ") + "\n")
	}

	sb.WriteString("\nValid indicators you may emit (ONLY choose from this list): ")
	sb.WriteString("port_scan, c2_beaconing, lateral_movement, dns_tunneling, data_exfiltration, ")
	sb.WriteString("protocol_anomaly, geo_ip_anomaly, remote_access_anomaly, network_reconnaissance, ")
	sb.WriteString("suspicious_dns_query, connection_flood, unauthorized_service, encrypted_c2, ")
	sb.WriteString("domain_generation_algo, low_and_slow_exfiltration.\n\n")
	sb.WriteString("Respond ONLY with valid JSON (no prose): " +
		`{"indicators":["..."],"confidence":0.0,"rationale":"..."}`)

	return sb.String()
}

// inferNetworkRiskLevel maps existing indicators to a risk level.
func inferNetworkRiskLevel(indicators []string) string {
	criticalSet := map[string]bool{
		"c2_beaconing": true, "domain_generation_algo": true, "encrypted_c2": true,
		"data_exfiltration": true,
	}
	highSet := map[string]bool{
		"lateral_movement": true, "dns_tunneling": true, "low_and_slow_exfiltration": true,
		"network_reconnaissance": true,
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

// extractNovelNetworkIndicators parses the model's JSON summary and returns
// indicators that are valid and not already in existing.
func extractNovelNetworkIndicators(summary string, existing []string) []string {
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

	var classification networkAIClassification
	if err := json.Unmarshal([]byte(snippet), &classification); err != nil {
		return nil
	}

	var novel []string
	for _, ind := range classification.Indicators {
		ind = strings.TrimSpace(strings.ToLower(ind))
		if knownNetworkIndicators[ind] && !existingSet[ind] {
			novel = append(novel, ind)
		}
	}
	return novel
}
