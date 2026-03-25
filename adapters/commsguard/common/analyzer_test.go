package commsguardcommon

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"
)

// stubEnricher is a test double for the Enricher interface.
type stubEnricher struct {
	indicators []string
	assessment *CommsModelAssessment
}

func (s *stubEnricher) Enrich(_ context.Context, _ *CommsEvent, _ []string) ([]string, *CommsModelAssessment) {
	return s.indicators, s.assessment
}

func newAnalyzer() *ThreatAnalyzer {
	return NewThreatAnalyzer()
}

func makeEvent(content string) *CommsEvent {
	return &CommsEvent{
		EventType:   "message_received",
		Channel:     "whatsapp",
		Timestamp:   time.Now(),
		SenderID:    "15550000001",
		RecipientID: "15550000002",
		MessageID:   "test-msg-1",
		Content:     content,
	}
}

func containsIndicator(indicators []string, target string) bool {
	for _, ind := range indicators {
		if ind == target {
			return true
		}
	}
	return false
}

// TestNoEnricherNoContentIndicators verifies that without an AI model configured,
// Analyze returns no content-based indicators for any message.
func TestNoEnricherNoContentIndicators(t *testing.T) {
	a := newAnalyzer()
	indicators := a.Analyze(makeEvent("Click here to claim your reward http://evil.xyz"))
	if len(indicators) != 0 {
		t.Errorf("expected no indicators without enricher, got %v", indicators)
	}
}

// TestAIPhishingDetection verifies that phishing indicators from the AI model
// are returned by Analyze.
func TestAIPhishingDetection(t *testing.T) {
	a := newAnalyzer()
	a.enricher = &stubEnricher{
		indicators: []string{"phishing"},
		assessment: &CommsModelAssessment{
			RiskLevel:         "high",
			Confidence:        0.95,
			Summary:           "Phishing attempt detected",
			ProviderName:      "claude",
			RecommendedAction: "block",
			Indicators:        []string{"phishing"},
		},
	}
	event := makeEvent("Urgent: verify your account now")
	indicators := a.Analyze(event)
	if !containsIndicator(indicators, "phishing") {
		t.Errorf("expected phishing indicator from AI enricher, got %v", indicators)
	}
	if event.RawData["ai_provider"] != "claude" {
		t.Errorf("expected ai_provider=claude in RawData, got %v", event.RawData["ai_provider"])
	}
}

// TestAIAssessmentWrittenToRawData verifies all AI assessment fields are stored on the event.
func TestAIAssessmentWrittenToRawData(t *testing.T) {
	a := newAnalyzer()
	a.enricher = &stubEnricher{
		indicators: []string{"credential_harvesting"},
		assessment: &CommsModelAssessment{
			RiskLevel:         "high",
			Confidence:        0.87,
			Summary:           "Credential harvesting attempt",
			ProviderName:      "gemini",
			RecommendedAction: "block",
			Indicators:        []string{"credential_harvesting"},
		},
	}
	event := makeEvent("Enter your password to continue")
	a.Analyze(event)
	checks := map[string]interface{}{
		"ai_risk_level":         "high",
		"ai_provider":           "gemini",
		"ai_recommended_action": "block",
	}
	for key, want := range checks {
		if got := event.RawData[key]; got != want {
			t.Errorf("RawData[%q] = %v, want %v", key, got, want)
		}
	}
}

// TestCrossChannelCorrelation verifies cross-channel attack detection using AI indicators.
func TestCrossChannelCorrelation(t *testing.T) {
	a := newAnalyzer()
	a.enricher = &stubEnricher{
		indicators: []string{"phishing"},
		assessment: &CommsModelAssessment{RiskLevel: "high", Confidence: 0.9},
	}
	tracker := NewCrossChannelTracker(24*time.Hour, zap.NewNop())
	a.crossChannel = tracker

	// First event on whatsapp.
	e1 := &CommsEvent{
		Channel: "whatsapp", SenderID: "attacker-1",
		Content: "phishing message", Timestamp: time.Now(),
	}
	a.Analyze(e1)

	// Same sender on telegram — should trigger cross_channel_attack.
	e2 := &CommsEvent{
		Channel: "telegram", SenderID: "attacker-1",
		Content: "phishing message", Timestamp: time.Now(),
	}
	indicators := a.Analyze(e2)
	if !containsIndicator(indicators, "cross_channel_attack") {
		t.Errorf("expected cross_channel_attack indicator, got %v", indicators)
	}
}

// TestNilAssessmentNoRawDataPanic verifies Analyze handles a nil assessment gracefully.
func TestNilAssessmentNoRawDataPanic(t *testing.T) {
	a := newAnalyzer()
	a.enricher = &stubEnricher{indicators: []string{"spam"}, assessment: nil}
	event := makeEvent("buy now!")
	indicators := a.Analyze(event)
	if !containsIndicator(indicators, "spam") {
		t.Errorf("expected spam indicator even with nil assessment, got %v", indicators)
	}
	if event.RawData != nil {
		t.Errorf("expected nil RawData when assessment is nil, got %v", event.RawData)
	}
}
