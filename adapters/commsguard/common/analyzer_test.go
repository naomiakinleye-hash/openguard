package commsguardcommon

import (
	"testing"
	"time"
)

func newAnalyzer() *ThreatAnalyzer {
	return NewThreatAnalyzer(20, 60*time.Second, true)
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

// TestPhishingRewardScamNoURL verifies that the original failing case is now detected.
// "Click the link to claim your reward of 1million" has no URL in the text but contains
// both a click-action phrase ("click the link") and a reward scam phrase ("claim your reward",
// "1million"). Both alone should result in a "phishing" indicator.
func TestPhishingRewardScamNoURL(t *testing.T) {
	a := newAnalyzer()
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "original failing message",
			content: "Click the link to claim your reward of 1million",
		},
		{
			name:    "reward scam with prize",
			content: "Congratulations you have won our prize of 1 million dollars!",
		},
		{
			name:    "lottery winner no url",
			content: "You have been selected as our lottery winner. Collect your reward now.",
		},
		{
			name:    "prize claim phrase",
			content: "Claim your prize before it expires.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indicators := a.Analyze(makeEvent(tt.content))
			if !containsIndicator(indicators, "phishing") {
				t.Errorf("expected 'phishing' indicator for message %q, got %v", tt.content, indicators)
			}
		})
	}
}

// TestPhishingWithURL verifies the existing URL+keyword path still works.
func TestPhishingWithURL(t *testing.T) {
	a := newAnalyzer()
	indicators := a.Analyze(makeEvent("Please click here http://evil.xyz/login to verify your account"))
	if !containsIndicator(indicators, "phishing") {
		t.Errorf("expected phishing indicator for URL+keyword message, got %v", indicators)
	}
}

// TestClickTheLinkWithURL verifies "click the link" now matches as a phishing keyword.
func TestClickTheLinkWithURL(t *testing.T) {
	a := newAnalyzer()
	indicators := a.Analyze(makeEvent("Click the link http://malicious.tk/verify to get your prize"))
	if !containsIndicator(indicators, "phishing") {
		t.Errorf("expected phishing indicator for 'click the link' + URL, got %v", indicators)
	}
}

// TestCleanMessageNotFlagged verifies benign messages are not flagged.
func TestCleanMessageNotFlagged(t *testing.T) {
	a := newAnalyzer()
	indicators := a.Analyze(makeEvent("Hey, are we still on for dinner tonight?"))
	if containsIndicator(indicators, "phishing") {
		t.Errorf("clean message incorrectly flagged as phishing")
	}
}

// TestSuspiciousLinkDetection verifies suspicious TLD links are flagged.
func TestSuspiciousLinkDetection(t *testing.T) {
	a := newAnalyzer()
	indicators := a.Analyze(makeEvent("Check this out: http://free-iphone.tk/claim"))
	if !containsIndicator(indicators, "suspicious_link") {
		t.Errorf("expected suspicious_link indicator, got %v", indicators)
	}
}

// TestSocialEngineeringDetection verifies social engineering is still detected.
func TestSocialEngineeringDetection(t *testing.T) {
	a := newAnalyzer()
	indicators := a.Analyze(makeEvent("This is your bank calling, we need you to confirm your details"))
	if !containsIndicator(indicators, "social_engineering") {
		t.Errorf("expected social_engineering indicator, got %v", indicators)
	}
}
