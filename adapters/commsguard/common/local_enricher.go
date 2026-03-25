package commsguardcommon

import (
	"context"
	"strings"
)

// LocalEnricher applies pattern-based threat detection as a fallback when the
// AI model provider (model-gateway) is unavailable or unconfigured.
//
// It is intentionally lightweight — heavy NLP belongs to the AI layer.  The
// goal here is to catch unambiguous, high-signal threats (phishing lure +
// external URL, credential request) so that the pipeline produces actionable
// events even without a running model-gateway.
//
// Wire it as the primary Enricher when no ModelIntelClient is configured, or
// as the last enricher in a chain so events are never left unscored.
type LocalEnricher struct{}

// Channel-agnostic phishing/reward lure phrases.
var phishingLurePhrases = []string{
	"claim your", "claim reward", "claim prize", "claim your reward",
	"you have won", "you've won", "you won", "congratulations you",
	"selected winner", "lottery winner", "lucky winner",
	"reward of", "prize of", "gift of", "won a", "win a",
	"million dollar", "million naira", "million usd", "1million",
	"1 million", "free gift", "free money",
	"click to claim", "click to collect", "click to receive",
	"act now to claim", "collect your reward",
}

// Urgency + action phrases that accompany suspicious links.
var urgencyPhrases = []string{
	"click the link", "click here", "click below", "tap the link",
	"urgent", "immediately", "act now", "limited time",
	"account will be", "account suspended", "verify now", "verify your account",
	"expires soon", "last chance",
}

// Credential harvesting patterns.
var credPhrases = []string{
	"enter your password", "enter password", "your password",
	"otp", "one-time pin", "one time pin", "one-time code",
	"security code", "authentication code",
	"log in here", "login here", "sign in here",
	"enter your credentials", "submit your credentials",
	"verify your identity", "confirm your details",
}

// Enrich classifies the event using pattern matching and returns novel
// indicators (those not already in knownIndicators) plus a lightweight
// assessment so the orchestrator can build an AI-style decision.
func (e *LocalEnricher) Enrich(_ context.Context, event *CommsEvent, knownIndicators []string) ([]string, *CommsModelAssessment) {
	if event.Content == "" {
		return nil, nil
	}

	body := strings.ToLower(event.Content)
	known := make(map[string]bool, len(knownIndicators))
	for _, ind := range knownIndicators {
		known[ind] = true
	}

	var detected []string

	// Credential harvesting — highest priority, check first.
	if !known["credential_harvesting"] && containsAnyPhrase(body, credPhrases) {
		detected = append(detected, "credential_harvesting")
	}

	// Phishing: external URL + reward/lure language.
	hasURL := strings.Contains(body, "http://") || strings.Contains(body, "https://")
	hasLure := containsAnyPhrase(body, phishingLurePhrases)
	hasUrgency := containsAnyPhrase(body, urgencyPhrases)

	if !known["phishing"] {
		if hasURL && hasLure {
			detected = append(detected, "phishing")
		} else if hasURL && hasUrgency {
			detected = append(detected, "phishing")
		}
	}

	// Suspicious link: URL present but no strong phishing/credential signal.
	if !known["suspicious_link"] && !known["phishing"] && !known["credential_harvesting"] && hasURL {
		detected = append(detected, "suspicious_link")
	}

	if len(detected) == 0 {
		return nil, nil
	}

	// Build a minimal assessment so the event carries AI-style metadata even
	// when no real model is involved.
	riskLevel := "low"
	confidence := 0.55
	summary := "Pattern-based detection (no AI model available)"

	for _, ind := range detected {
		switch ind {
		case "credential_harvesting":
			riskLevel = "critical"
			confidence = 0.90
			summary = "Message requests credentials — high-confidence credential-harvesting lure detected by local pattern matcher."
		case "phishing":
			if riskLevel != "critical" {
				riskLevel = "high"
				confidence = 0.80
				summary = "Message contains an external URL combined with financial reward or urgency language — phishing lure detected by local pattern matcher."
			}
		case "suspicious_link":
			if riskLevel == "low" {
				riskLevel = "medium"
				confidence = 0.65
				summary = "Message contains an external URL — flagged for review by local pattern matcher."
			}
		}
	}

	assessment := &CommsModelAssessment{
		RiskLevel:         riskLevel,
		Confidence:        confidence,
		Summary:           summary,
		ProviderName:      "local-enricher",
		RecommendedAction: recommendedLocalAction(riskLevel),
		Indicators:        detected,
	}
	return detected, assessment
}

func recommendedLocalAction(riskLevel string) string {
	switch riskLevel {
	case "critical", "high":
		return "block"
	case "medium":
		return "escalate"
	default:
		return "allow"
	}
}

// containsAnyPhrase returns true if body contains any of the given phrases.
func containsAnyPhrase(body string, phrases []string) bool {
	for _, p := range phrases {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}
