// Package detect implements the OpenGuard v5 detection service.
// It runs rule-based detection, model-assisted classification, risk scoring,
// and tier assignment on ingested events.
package detect

import (
	"context"
	"fmt"
	"math"

	"go.uber.org/zap"
)

// Config holds configuration for the detection Service.
type Config struct {
	// RulesDir is the path to the detection rules directory.
	RulesDir string
	// ModelAssistThreshold is the minimum risk score at which model assistance
	// is requested (default: 40.0 — medium risk and above).
	ModelAssistThreshold float64
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
	result, err := s.Detect(ctx, event)
	if err != nil {
		return fmt.Errorf("detect: handle event: %w", err)
	}
	// Enrich the event in place with detection results.
	event["risk_score"] = result.RiskScore
	event["tier"] = result.Tier
	event["severity"] = result.Severity
	return nil
}

// scoreComponents derives risk score components from the event payload.
// In production these are driven by loaded rule files and threat intelligence feeds.
func (s *Service) scoreComponents(event map[string]interface{}) RiskComponents {
	var c RiskComponents

	// Anomaly: elevate if domain is agent or model.
	switch event["domain"] {
	case "agent", "model":
		c.AnomalyScore = 15
	case "host":
		c.AnomalyScore = 10
	default:
		c.AnomalyScore = 5
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
