// Package detect implements the OpenGuard v5 detection service.
// It runs rule-based detection, model-assisted classification, risk scoring,
// and tier assignment on ingested events.
package detect

import (
	"context"
	"fmt"
	"math"
	"strings"

	"go.uber.org/zap"

	"github.com/DiniMuhd7/openguard/services/baseline"
)

// EventSink receives detected events for persistence.
type EventSink interface {
	Add(event map[string]interface{})
}

// Config holds configuration for the detection Service.
type Config struct {
	// RulesDir is the path to the detection rules directory.
	RulesDir string
	// ModelAssistThreshold is the minimum risk score at which model assistance
	// is requested (default: 40.0 — medium risk and above).
	ModelAssistThreshold float64
	// Sink is an optional EventSink that receives detected events for persistence.
	Sink EventSink
	// Baseline is an optional behavioural baseline engine; when set, drift scores
	// are added to the anomaly component of the risk score.
	Baseline *baseline.Engine
}

// RiskComponents holds the four components of the composite risk score.
type RiskComponents struct {
	// AnomalyScore is the anomaly detection component (0–25).
	AnomalyScore float64
	// PolicyViolationScore is the policy violation component (0–25).
	PolicyViolationScore float64
	// ThreatIntelScore is the threat intelligence component (0–25).
	ThreatIntelScore float64
	// AssetCriticalityScore is the asset criticality component (0–25).
	AssetCriticalityScore float64
}

// DetectionResult is the output of the detection pipeline for a single event.
type DetectionResult struct {
	// EventID is the identifier of the analyzed event.
	EventID string
	// RiskScore is the composite risk score R = anomaly + policy_violation + threat_intel + asset_criticality.
	RiskScore float64
	// Tier is the response tier assigned based on risk score.
	Tier string
	// Severity is the severity label.
	Severity string
	// MatchedRules lists rule IDs that fired on this event.
	MatchedRules []string
	// PolicyCitations lists policy IDs relevant to this event.
	PolicyCitations []string
	// Components contains the individual risk score components.
	Components RiskComponents
}

// Service is the detection service.
type Service struct {
	cfg    Config
	logger *zap.Logger
}

// NewService constructs a new detection Service.
func NewService(cfg Config, logger *zap.Logger) *Service {
	if cfg.ModelAssistThreshold == 0 {
		cfg.ModelAssistThreshold = 40.0
	}
	return &Service{cfg: cfg, logger: logger}
}

// Detect runs the detection pipeline on a validated event and returns a DetectionResult.
// R = anomaly + policy_violation + threat_intel + asset_criticality (clamped to [0, 100])
func (s *Service) Detect(ctx context.Context, event map[string]interface{}) (*DetectionResult, error) {
	eventID, _ := event["event_id"].(string)

	components := s.scoreComponents(event)
	riskScore := math.Min(
		components.AnomalyScore+components.PolicyViolationScore+components.ThreatIntelScore+components.AssetCriticalityScore,
		100.0,
	)

	tier := assignTier(riskScore)
	severity := tierToSeverity(tier)

	s.logger.Info("detect: event scored",
		zap.String("event_id", eventID),
		zap.Float64("risk_score", riskScore),
		zap.String("tier", tier),
		zap.String("severity", severity),
	)

	return &DetectionResult{
		EventID:    eventID,
		RiskScore:  riskScore,
		Tier:       tier,
		Severity:   severity,
		Components: components,
	}, nil
}

// HandleEvent implements the ingest.EventHandler interface so the detection
// service can be wired directly into the ingest pipeline.
func (s *Service) HandleEvent(ctx context.Context, event map[string]interface{}) error {
	// Preserve the adapter's calibrated risk score before running the pipeline.
	// Adapter scores are domain-specific and authoritative for their indicator set
	// (e.g. phishing=75, credential_harvesting=92). The detect service is additive —
	// it enriches with asset criticality and threat intel but must never decrease
	// a score that was already computed from known indicators.
	adapterRisk, _ := event["risk_score"].(float64)

	result, err := s.Detect(ctx, event)
	if err != nil {
		return fmt.Errorf("detect: handle event: %w", err)
	}

	// Take the higher of adapter-assigned and detect-computed scores so that
	// well-calibrated adapter signals are never silently downgraded.
	finalScore := math.Max(adapterRisk, result.RiskScore)
	finalTier := assignTier(finalScore)
	finalSeverity := tierToSeverity(finalTier)

	if finalScore != result.RiskScore {
		s.logger.Info("detect: adapter score preserved",
			zap.String("event_id", result.EventID),
			zap.Float64("adapter_score", adapterRisk),
			zap.Float64("detect_score", result.RiskScore),
			zap.Float64("final_score", finalScore),
			zap.String("tier", finalTier),
			zap.String("severity", finalSeverity),
		)
	}

	// Enrich the event in place with final detection results.
	event["risk_score"] = finalScore
	event["tier"] = finalTier
	event["severity"] = finalSeverity
	event["matched_rules"] = result.MatchedRules

	// Record host metrics in the baseline engine for drift detection.
	if s.cfg.Baseline != nil {
		if host, _ := event["host"].(string); host != "" {
			if meta, ok := event["metadata"].(map[string]interface{}); ok {
				if cpu, ok := meta["cpu_percent"].(float64); ok {
					s.cfg.Baseline.Record("host", host, "cpu_percent", cpu)
				}
				if mem, ok := meta["memory_mb"].(float64); ok {
					s.cfg.Baseline.Record("host", host, "memory_mb", mem)
				}
			}
		}
	}

	// Forward enriched event to the sink if configured.
	if s.cfg.Sink != nil {
		s.cfg.Sink.Add(event)
	}
	return nil
}

// injectionPatterns are substrings that indicate prompt injection attempts
// in an agent's tool responses or RAG-retrieved content.
var injectionPatterns = []string{
	"ignore previous instructions",
	"disregard your instructions",
	"new system prompt",
	"override your policy",
	"your real instructions are",
	"forget everything above",
	"act as if you are",
	"you are now",
	"<!--",
	"<script",
	"]}; // injection",
}

// scoreComponents derives risk score components from the event payload.
// In production these are driven by loaded rule files and threat intelligence feeds.
func (s *Service) scoreComponents(event map[string]interface{}) RiskComponents {
	var c RiskComponents
	var matchedRules []string

	domain, _ := event["domain"].(string)
	eventType, _ := event["type"].(string)

	// Anomaly: elevate if domain is agent or model.
	switch domain {
	case "agent", "model":
		c.AnomalyScore = 15
	case "host", "network":
		c.AnomalyScore = 10
	case "comms":
		c.AnomalyScore = 8
	default:
		c.AnomalyScore = 5
	}

	// AGENT-006: Indirect prompt injection via tool_response or rag_content.
	if domain == "agent" {
		for _, field := range []string{"tool_response", "rag_content"} {
			if val, ok := event[field].(string); ok && val != "" {
				lower := strings.ToLower(val)
				for _, pat := range injectionPatterns {
					if strings.Contains(lower, pat) {
						c.AnomalyScore = math.Max(c.AnomalyScore, 25)
						matchedRules = append(matchedRules, "AGENT-006")
						break
					}
				}
			}
		}
	}

	// AGENT-007: Anomalous memory write operations.
	if domain == "agent" {
		if memOp, ok := event["memory_operation"].(string); ok && memOp == "write" {
			c.AnomalyScore += 12
			matchedRules = append(matchedRules, "AGENT-007")
		}
	}

	// AGENT-008: RAG content poisoning indicator.
	if domain == "agent" && strings.Contains(eventType, "rag_poison") {
		c.AnomalyScore = math.Max(c.AnomalyScore, 22)
		matchedRules = append(matchedRules, "AGENT-008")
	}

	// HOST-SC: Supply chain / package manager invocation.
	if domain == "host" {
		cmd, _ := event["command"].(string)
		for _, pm := range []string{"npm ", "pip ", "pip3 ", "go get", "go install", "apt install", "brew install", "cargo install", "yarn add"} {
			if strings.Contains(strings.ToLower(cmd), pm) {
				c.AnomalyScore += 8
				matchedRules = append(matchedRules, "HOST-SC-001")
				break
			}
		}
	}

	// Baseline drift scoring.
	if s.cfg.Baseline != nil {
		if host, _ := event["host"].(string); host != "" {
			if meta, ok := event["metadata"].(map[string]interface{}); ok {
				if cpu, ok := meta["cpu_percent"].(float64); ok {
					drift := s.cfg.Baseline.DriftScore("host", host, "cpu_percent", cpu)
					if drift > 0 {
						c.AnomalyScore = math.Min(c.AnomalyScore+drift, 25)
						matchedRules = append(matchedRules, "BASELINE-CPU-DRIFT")
					}
				}
			}
		}
	}

	// Store matched rules in the event for enrichment.
	if len(matchedRules) > 0 {
		event["matched_rules"] = matchedRules
	}

	// Policy violation: use existing risk_score as a hint if present.
	if rs, ok := event["risk_score"].(float64); ok && rs > 0 {
		c.PolicyViolationScore = math.Min(rs/4, 25)
	}

	// Asset criticality: look for criticality hint in metadata.
	if meta, ok := event["metadata"].(map[string]interface{}); ok {
		if crit, ok := meta["asset_criticality"].(string); ok {
			switch crit {
			case "critical":
				c.AssetCriticalityScore = 25
			case "high":
				c.AssetCriticalityScore = 18
			case "medium":
				c.AssetCriticalityScore = 10
			default:
				c.AssetCriticalityScore = 5
			}
		}
	}

	return c
}

// assignTier assigns a response tier based on the composite risk score.
//
//	T0: 0–19, T1: 20–39, T2: 40–59, T3: 60–79, T4: 80–100
func assignTier(score float64) string {
	switch {
	case score >= 80:
		return "T4"
	case score >= 60:
		return "T3"
	case score >= 40:
		return "T2"
	case score >= 20:
		return "T1"
	default:
		return "T0"
	}
}

// tierToSeverity maps response tiers to severity labels.
func tierToSeverity(tier string) string {
	switch tier {
	case "T4":
		return "critical"
	case "T3":
		return "high"
	case "T2":
		return "medium"
	case "T1":
		return "low"
	default:
		return "info"
	}
}
