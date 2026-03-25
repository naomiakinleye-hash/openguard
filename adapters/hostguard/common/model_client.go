// Package hostguardcommon provides shared types and utilities for the HostGuard sensor.
package hostguardcommon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// knownHostIndicators is the canonical set of HostGuard threat indicators the
// AI model is allowed to emit. Values outside this set are discarded to prevent
// prompt-injection attacks from injecting arbitrary indicators.
var knownHostIndicators = map[string]bool{
	"privilege_escalation":          true,
	"startup_persistence":           true,
	"suspicious_path":               true,
	"hidden_process_detected":       true,
	"data_exfiltration":             true,
	"lateral_movement":              true,
	"c2_beaconing":                  true,
	"dns_tunneling":                 true,
	"process_injection":             true,
	"credential_dumping":            true,
	"container_escape":              true,
	"supply_chain_risk":             true,
	"rootkit_detection":             true,
	"suspicious_network_connection": true,
	"suspicious_file_access":        true,
	"resource_hijacking":            true,
	"living_off_the_land":           true,
	"cloud_metadata_access":         true,
	"kernel_exploit":                true,
	"firmware_tampering":            true,
}

// hostModelIntelRequest mirrors the model-gateway's modelRequest JSON schema.
type hostModelIntelRequest struct {
	EventID    string   `json:"event_id"`
	AgentID    string   `json:"agent_id"`
	Prompt     string   `json:"prompt"`
	RiskLevel  string   `json:"risk_level"`
	Domain     string   `json:"domain"`
	Indicators []string `json:"indicators"`
}

// hostModelIntelResponse mirrors the model-gateway's modelResponse JSON schema.
type hostModelIntelResponse struct {
	EventID string                 `json:"event_id"`
	Result  *hostModelIntelResult  `json:"result,omitempty"`
	Error   string                 `json:"error,omitempty"`
}

// hostModelIntelResult holds the fields from AnalysisResult that we use.
type hostModelIntelResult struct {
	ProviderName string  `json:"provider_name"`
	Summary      string  `json:"summary"`
	Confidence   float64 `json:"confidence"`
	RiskLevel    string  `json:"risk_level"`
}

// hostAIClassification is the JSON structure we instruct the model to return
// inside its summary. We parse it back to extract canonical indicators.
type hostAIClassification struct {
	Indicators []string `json:"indicators"`
	Confidence float64  `json:"confidence"`
	Rationale  string   `json:"rationale"`
}

// HostModelIntelClient sends HostEvents to the model-gateway agent for
// AI-powered threat enrichment using NATS request-reply semantics.
//
// The client is nil-safe — callers may pass a nil *HostModelIntelClient and
// call Enrich; it will simply return nil without panicking.
//
// It is safe for concurrent use.
type HostModelIntelClient struct {
	nc      *nats.Conn
	topic   string
	timeout time.Duration
	agentID string
	logger  *zap.Logger
}

// NewHostModelIntelClient creates a HostModelIntelClient that dispatches AI
// enrichment requests to the model-gateway via NATS.
//
//   - nc      — shared NATS connection (caller owns lifecycle).
//   - topic   — NATS subject the model-gateway is subscribed to
//               (default: "openguard.modelguard.requests").
//   - timeout — per-request deadline (default: 10 s).
//   - agentID — identifies HostGuard to the model-gateway rate-limiter
//               (default: "hostguard").
func NewHostModelIntelClient(nc *nats.Conn, topic string, timeout time.Duration, agentID string, logger *zap.Logger) *HostModelIntelClient {
	if topic == "" {
		topic = "openguard.modelguard.requests"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if agentID == "" {
		agentID = "hostguard"
	}
	return &HostModelIntelClient{
		nc:      nc,
		topic:   topic,
		timeout: timeout,
		agentID: agentID,
		logger:  logger,
	}
}

// Enrich sends the HostEvent to the model-gateway for AI threat classification
// and returns any NEW indicators not already present in existingIndicators.
//
// Errors are handled gracefully: on timeout or unavailability the method returns
// nil so the caller falls back to heuristic-only results.
func (m *HostModelIntelClient) Enrich(ctx context.Context, event *HostEvent, existingIndicators []string) []string {
	if m == nil || m.nc == nil {
		return nil
	}

	eventID := fmt.Sprintf("hostguard-%d", time.Now().UnixNano())

	req := hostModelIntelRequest{
		EventID:    eventID,
		AgentID:    m.agentID,
		Prompt:     buildHostIntelPrompt(event, existingIndicators),
		RiskLevel:  inferHostRiskLevel(existingIndicators),
		Domain:     "host",
		Indicators: existingIndicators,
	}

	data, err := json.Marshal(req)
	if err != nil {
		m.logger.Warn("host-model-intel: marshal request failed", zap.Error(err))
		return nil
	}

	reqCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	replyMsg, err := m.nc.RequestWithContext(reqCtx, m.topic, data)
	if err != nil {
		// Model-gateway may not be deployed; log at Debug to avoid noise.
		m.logger.Debug("host-model-intel: request failed (model-gateway unavailable?)",
			zap.String("event_type", event.EventType),
			zap.String("hostname", event.Hostname),
			zap.String("event_id", eventID),
			zap.Error(err),
		)
		return nil
	}

	var resp hostModelIntelResponse
	if err := json.Unmarshal(replyMsg.Data, &resp); err != nil {
		m.logger.Warn("host-model-intel: parse response failed", zap.Error(err))
		return nil
	}
	if resp.Error != "" {
		m.logger.Debug("host-model-intel: model-gateway returned error",
			zap.String("event_id", eventID),
			zap.String("error", resp.Error),
		)
		return nil
	}
	if resp.Result == nil {
		return nil
	}

	novel := extractNovelHostIndicators(resp.Result.Summary, existingIndicators)
	if len(novel) > 0 {
		m.logger.Info("host-model-intel: AI enrichment added indicators",
			zap.String("event_type", event.EventType),
			zap.String("hostname", event.Hostname),
			zap.String("provider", resp.Result.ProviderName),
			zap.Float64("confidence", resp.Result.Confidence),
			zap.Strings("novel_indicators", novel),
		)
	}
	return novel
}

// buildHostIntelPrompt constructs a structured prompt instructing the model to
// return a JSON classification of the host event's threat indicators.
func buildHostIntelPrompt(event *HostEvent, existing []string) string {
	var sb strings.Builder

	sb.WriteString("You are a host security threat analyst.\n\n")
	sb.WriteString("Analyze the following host security event for advanced threats.\n\n")

	sb.WriteString("Platform: " + event.Platform + "\n")
	sb.WriteString("Hostname: " + event.Hostname + "\n")
	sb.WriteString("Event Type: " + event.EventType + "\n")

	if event.Process != nil {
		p := event.Process
		sb.WriteString(fmt.Sprintf("Process: %s (PID=%d, PPID=%d, user=%s)\n",
			p.Name, p.PID, p.PPID, p.Username))
		if p.CmdLine != "" {
			sb.WriteString("Command: " + p.CmdLine + "\n")
		}
		if p.ExePath != "" {
			sb.WriteString("Executable: " + p.ExePath + "\n")
		}
	}

	if event.FileIO != nil {
		sb.WriteString(fmt.Sprintf("File Operation: %s on %s (by %s)\n",
			event.FileIO.Operation, event.FileIO.Path, event.FileIO.ProcessName))
	}

	if event.DNSQuery != nil {
		sb.WriteString(fmt.Sprintf("DNS Query: %s (type=%s, resolver=%s)\n",
			event.DNSQuery.QueryName, event.DNSQuery.QueryType, event.DNSQuery.Resolver))
	}

	if event.StartupItem != nil {
		sb.WriteString(fmt.Sprintf("Startup Item: %s (type=%s, cmd=%s)\n",
			event.StartupItem.Name, event.StartupItem.Type, event.StartupItem.Command))
	}

	if event.HiddenProcess != nil {
		sb.WriteString("Hidden Process Detected\n")
	}

	if len(existing) > 0 {
		sb.WriteString("Already detected indicators: " + strings.Join(existing, ", ") + "\n")
	}

	sb.WriteString("\nValid indicators you may emit (ONLY choose from this list): ")
	sb.WriteString("privilege_escalation, startup_persistence, suspicious_path, hidden_process_detected, ")
	sb.WriteString("data_exfiltration, lateral_movement, c2_beaconing, dns_tunneling, process_injection, ")
	sb.WriteString("credential_dumping, container_escape, supply_chain_risk, rootkit_detection, ")
	sb.WriteString("suspicious_network_connection, suspicious_file_access, resource_hijacking, ")
	sb.WriteString("living_off_the_land, cloud_metadata_access, kernel_exploit, firmware_tampering.\n\n")
	sb.WriteString("Respond ONLY with valid JSON (no prose): " +
		`{"indicators":["..."],"confidence":0.0,"rationale":"..."}`)

	return sb.String()
}

// inferHostRiskLevel returns a risk level string based on the severity of
// already-detected indicators, used to prioritise model-gateway routing.
func inferHostRiskLevel(indicators []string) string {
	criticalSet := map[string]bool{
		"privilege_escalation": true, "c2_beaconing": true, "process_injection": true,
		"credential_dumping": true, "container_escape": true, "rootkit_detection": true,
		"kernel_exploit": true, "firmware_tampering": true,
	}
	highSet := map[string]bool{
		"lateral_movement": true, "dns_tunneling": true, "data_exfiltration": true,
		"startup_persistence": true, "living_off_the_land": true, "hidden_process_detected": true,
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

// extractNovelHostIndicators parses the model's JSON summary and returns
// indicators that are valid (in knownHostIndicators) and not already in existing.
func extractNovelHostIndicators(summary string, existing []string) []string {
	existingSet := make(map[string]bool, len(existing))
	for _, i := range existing {
		existingSet[i] = true
	}

	// Extract JSON object from summary (model may wrap it in prose).
	start := strings.Index(summary, "{")
	end := strings.LastIndex(summary, "}")
	if start == -1 || end <= start {
		return nil
	}
	snippet := summary[start : end+1]

	var classification hostAIClassification
	if err := json.Unmarshal([]byte(snippet), &classification); err != nil {
		return nil
	}

	var novel []string
	for _, ind := range classification.Indicators {
		ind = strings.TrimSpace(strings.ToLower(ind))
		if knownHostIndicators[ind] && !existingSet[ind] {
			novel = append(novel, ind)
		}
	}
	return novel
}
