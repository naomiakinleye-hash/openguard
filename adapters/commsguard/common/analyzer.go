// Package commsguardcommon provides shared types and utilities for the CommsGuard sensor.
package commsguardcommon

import (
	"context"
)

// Enricher is the interface for AI-powered threat enrichment of CommsEvents.
// ModelIntelClient implements this interface; tests may supply a stub.
type Enricher interface {
	Enrich(ctx context.Context, event *CommsEvent, knownIndicators []string) ([]string, *CommsModelAssessment)
}

// ThreatAnalyzer performs AI-driven threat analysis on CommsEvent messages.
// All analysis is delegated to the model-gateway via an Enricher.
// Cross-channel correlation supplements AI output.
type ThreatAnalyzer struct {
	// Primary threat detector — nil when model-gateway is not configured.
	enricher Enricher
	// Optional cross-channel correlation tracker.
	crossChannel *CrossChannelTracker
}

// NewThreatAnalyzer creates a new ThreatAnalyzer.
func NewThreatAnalyzer() *ThreatAnalyzer {
	return &ThreatAnalyzer{}
}

// WithModelIntelClient attaches the AI model provider as the primary threat detector.
// Pass nil to disable (default). The method returns the same *ThreatAnalyzer so it
// can be chained after NewThreatAnalyzer.
func (a *ThreatAnalyzer) WithModelIntelClient(client *ModelIntelClient) *ThreatAnalyzer {
	if client != nil {
		a.enricher = client
	}
	return a
}

// WithCrossChannelTracker attaches a cross-channel correlation tracker.
// Pass nil to disable cross-channel detection (default).
func (a *ThreatAnalyzer) WithCrossChannelTracker(tracker *CrossChannelTracker) *ThreatAnalyzer {
	a.crossChannel = tracker
	return a
}

// Analyze inspects a CommsEvent and returns a slice of threat indicator strings.
//
// The AI model provider is the sole source of threat classification. The event
// is forwarded to the model-gateway for semantic analysis; all indicators
// originate there. Cross-channel correlation then checks whether the same
// threat fingerprint has appeared across multiple channels within the
// look-back window.
func (a *ThreatAnalyzer) Analyze(event *CommsEvent) []string {
	var indicators []string

	// ── AI model provider ──────────────────────────────────────────────────────
	if a.enricher != nil {
		novel, assessment := a.enricher.Enrich(context.Background(), event, nil)
		indicators = append(indicators, novel...)
		if assessment != nil {
			if event.RawData == nil {
				event.RawData = make(map[string]interface{})
			}
			event.RawData["ai_risk_level"] = assessment.RiskLevel
			event.RawData["ai_confidence"] = assessment.Confidence
			event.RawData["ai_summary"] = assessment.Summary
			event.RawData["ai_provider"] = assessment.ProviderName
			event.RawData["ai_recommended_action"] = assessment.RecommendedAction
			event.RawData["ai_indicators"] = assessment.Indicators
		}
	}

	// ── Cross-channel correlation ──────────────────────────────────────────────
	if a.crossChannel != nil && len(indicators) > 0 {
		if a.crossChannel.Track(event, indicators) {
			indicators = append(indicators, "cross_channel_attack")
		}
	}

	return indicators
}
