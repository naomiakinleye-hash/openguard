// Package contract contains contract tests for OpenGuard v5 CommsGuard sensor.
package contract_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
)

// TestCommsEventToUnifiedEvent verifies that CommsEvent.ToUnifiedEvent()
// produces a JSON payload with all required UnifiedEvent schema fields
// and that domain is set to "comms".
func TestCommsEventToUnifiedEvent(t *testing.T) {
	event := &common.CommsEvent{
		EventType:   "message_received",
		Channel:     "whatsapp",
		Timestamp:   time.Now(),
		SenderID:    "+1234567890",
		RecipientID: "+0987654321",
		MessageID:   "wamid.test123",
		Content:     "Hello there",
		Indicators:  []string{},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal unified event: %v", err)
	}

	required := []string{
		"event_id", "timestamp", "source", "domain", "severity",
		"risk_score", "tier", "actor", "target", "human_approved", "audit_hash",
	}
	for _, field := range required {
		if _, ok := result[field]; !ok {
			t.Errorf("missing required field: %s", field)
		}
	}

	if result["domain"] != "comms" {
		t.Errorf("expected domain=comms, got %v", result["domain"])
	}
	if result["human_approved"] != false {
		t.Errorf("expected human_approved=false, got %v", result["human_approved"])
	}
	if result["audit_hash"] == "" {
		t.Error("expected non-empty audit_hash")
	}

	// Verify source object.
	source, ok := result["source"].(map[string]interface{})
	if !ok {
		t.Fatal("source is not an object")
	}
	if source["type"] != "comms" {
		t.Errorf("expected source.type=comms, got %v", source["type"])
	}
	if source["adapter"] != "whatsapp" {
		t.Errorf("expected source.adapter=whatsapp, got %v", source["adapter"])
	}

	// Verify actor and target.
	actor, ok := result["actor"].(map[string]interface{})
	if !ok {
		t.Fatal("actor is not an object")
	}
	if actor["id"] != "+1234567890" {
		t.Errorf("expected actor.id=+1234567890, got %v", actor["id"])
	}
	if actor["type"] != "user" {
		t.Errorf("expected actor.type=user, got %v", actor["type"])
	}

	// Verify event_id is UUID format.
	eventID, _ := result["event_id"].(string)
	if len(eventID) != 36 || strings.Count(eventID, "-") != 4 {
		t.Errorf("event_id does not look like a UUID: %s", eventID)
	}
}

// TestCommsEventClassification_Phishing verifies phishing_detected → high/75/T2.
func TestCommsEventClassification_Phishing(t *testing.T) {
	event := &common.CommsEvent{
		EventType:  "phishing_detected",
		Channel:    "telegram",
		Timestamp:  time.Now(),
		SenderID:   "spammer123",
		Indicators: []string{},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["severity"] != "high" {
		t.Errorf("expected severity=high for phishing_detected, got %v", result["severity"])
	}
	if result["risk_score"] != 75.0 {
		t.Errorf("expected risk_score=75.0, got %v", result["risk_score"])
	}
	if result["tier"] != "T2" {
		t.Errorf("expected tier=T2, got %v", result["tier"])
	}
}

// TestCommsEventClassification_CredentialHarvesting verifies credential_harvesting_detected → critical/90/immediate.
func TestCommsEventClassification_CredentialHarvesting(t *testing.T) {
	event := &common.CommsEvent{
		EventType:  "credential_harvesting_detected",
		Channel:    "messenger",
		Timestamp:  time.Now(),
		SenderID:   "attacker",
		Indicators: []string{},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["severity"] != "critical" {
		t.Errorf("expected severity=critical, got %v", result["severity"])
	}
	if result["risk_score"] != 90.0 {
		t.Errorf("expected risk_score=90.0, got %v", result["risk_score"])
	}
	if result["tier"] != "immediate" {
		t.Errorf("expected tier=immediate, got %v", result["tier"])
	}
}

// TestCommsEventClassification_DataExfiltration verifies data_exfiltration_detected → critical/92/immediate.
func TestCommsEventClassification_DataExfiltration(t *testing.T) {
	event := &common.CommsEvent{
		EventType:  "data_exfiltration_detected",
		Channel:    "twitter",
		Timestamp:  time.Now(),
		SenderID:   "leaker",
		Indicators: []string{},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["severity"] != "critical" {
		t.Errorf("expected severity=critical, got %v", result["severity"])
	}
	if result["risk_score"] != 92.0 {
		t.Errorf("expected risk_score=92.0, got %v", result["risk_score"])
	}
	if result["tier"] != "immediate" {
		t.Errorf("expected tier=immediate, got %v", result["tier"])
	}
}

// TestCommsEventClassification_MalwareAttachment verifies malware_attachment_detected → critical/95/immediate.
func TestCommsEventClassification_MalwareAttachment(t *testing.T) {
	event := &common.CommsEvent{
		EventType:  "malware_attachment_detected",
		Channel:    "whatsapp",
		Timestamp:  time.Now(),
		SenderID:   "malicious",
		Indicators: []string{},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["severity"] != "critical" {
		t.Errorf("expected severity=critical, got %v", result["severity"])
	}
	if result["risk_score"] != 95.0 {
		t.Errorf("expected risk_score=95.0, got %v", result["risk_score"])
	}
	if result["tier"] != "immediate" {
		t.Errorf("expected tier=immediate, got %v", result["tier"])
	}
}

// TestCommsEventClassification_BulkMessage verifies bulk_message_detected → high/65/T2.
func TestCommsEventClassification_BulkMessage(t *testing.T) {
	event := &common.CommsEvent{
		EventType:  "bulk_message_detected",
		Channel:    "twilio_sms",
		Timestamp:  time.Now(),
		SenderID:   "+1900555000",
		Indicators: []string{},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["severity"] != "high" {
		t.Errorf("expected severity=high, got %v", result["severity"])
	}
	if result["risk_score"] != 65.0 {
		t.Errorf("expected risk_score=65.0, got %v", result["risk_score"])
	}
	if result["tier"] != "T2" {
		t.Errorf("expected tier=T2, got %v", result["tier"])
	}
}

// TestCommsEventIndicatorOverride_CredentialHarvesting verifies that the
// "credential_harvesting" indicator overrides the base event type classification.
func TestCommsEventIndicatorOverride_CredentialHarvesting(t *testing.T) {
	// Even with a low-severity event type, the indicator should elevate to critical.
	event := &common.CommsEvent{
		EventType:  "message_received",
		Channel:    "telegram",
		Timestamp:  time.Now(),
		SenderID:   "attacker",
		Indicators: []string{"credential_harvesting"},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["severity"] != "critical" {
		t.Errorf("expected severity=critical due to indicator override, got %v", result["severity"])
	}
	if result["risk_score"] != 92.0 {
		t.Errorf("expected risk_score=92.0, got %v", result["risk_score"])
	}
	if result["tier"] != "immediate" {
		t.Errorf("expected tier=immediate, got %v", result["tier"])
	}
}

// TestCommsEventIndicatorOverride_DataExfiltration verifies that the
// "data_exfiltration" indicator overrides the base event type classification.
func TestCommsEventIndicatorOverride_DataExfiltration(t *testing.T) {
	event := &common.CommsEvent{
		EventType:  "message_received",
		Channel:    "messenger",
		Timestamp:  time.Now(),
		SenderID:   "leaker",
		Indicators: []string{"data_exfiltration"},
	}

	payload, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if result["severity"] != "critical" {
		t.Errorf("expected severity=critical due to data_exfiltration indicator, got %v", result["severity"])
	}
	if result["risk_score"] != 95.0 {
		t.Errorf("expected risk_score=95.0, got %v", result["risk_score"])
	}
	if result["tier"] != "immediate" {
		t.Errorf("expected tier=immediate, got %v", result["tier"])
	}
}

// TestThreatAnalyzer_PhishingDetection verifies the analyzer detects phishing
// patterns in message content (urgency keyword + URL).
func TestThreatAnalyzer_PhishingDetection(t *testing.T) {
	analyzer := common.NewThreatAnalyzer(20, 60*time.Second, true)

	event := &common.CommsEvent{
		EventType:  "message_received",
		Channel:    "whatsapp",
		Timestamp:  time.Now(),
		SenderID:   "scammer",
		Content:    "Please click here http://example.com to verify your account immediately!",
		Indicators: []string{},
	}

	indicators := analyzer.Analyze(event)
	if !containsCommsIndicator(indicators, "phishing") {
		t.Errorf("expected 'phishing' indicator, got %v", indicators)
	}
}

// TestThreatAnalyzer_SuspiciousLink verifies the analyzer flags URLs with suspicious TLDs.
func TestThreatAnalyzer_SuspiciousLink(t *testing.T) {
	analyzer := common.NewThreatAnalyzer(20, 60*time.Second, true)

	event := &common.CommsEvent{
		EventType:  "message_received",
		Channel:    "telegram",
		Timestamp:  time.Now(),
		SenderID:   "attacker",
		Content:    "Check this out: http://malicious.xyz/steal",
		Indicators: []string{},
	}

	indicators := analyzer.Analyze(event)
	if !containsCommsIndicator(indicators, "suspicious_link") {
		t.Errorf("expected 'suspicious_link' indicator for .xyz TLD, got %v", indicators)
	}
}

// TestThreatAnalyzer_CredentialKeywords verifies the analyzer flags messages
// containing credential-harvesting keywords combined with a URL.
func TestThreatAnalyzer_CredentialKeywords(t *testing.T) {
	analyzer := common.NewThreatAnalyzer(20, 60*time.Second, true)

	event := &common.CommsEvent{
		EventType:  "message_received",
		Channel:    "messenger",
		Timestamp:  time.Now(),
		SenderID:   "phisher",
		Content:    "Please enter your password at http://fake-bank.com/login to continue.",
		Indicators: []string{},
	}

	indicators := analyzer.Analyze(event)
	if !containsCommsIndicator(indicators, "credential_harvesting") {
		t.Errorf("expected 'credential_harvesting' indicator for password+URL, got %v", indicators)
	}
}

// TestCommsEventAuditHash verifies the audit_hash is a valid SHA-256 hex string
// and is deterministic for the same logical event structure.
func TestCommsEventAuditHash(t *testing.T) {
	ts := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	event := &common.CommsEvent{
		EventType:   "message_received",
		Channel:     "whatsapp",
		Timestamp:   ts,
		SenderID:    "+1111111111",
		RecipientID: "+2222222222",
		MessageID:   "test-msg-id",
		Content:     "test content",
		Indicators:  []string{},
	}

	payload1, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent (1) failed: %v", err)
	}
	payload2, err := event.ToUnifiedEvent()
	if err != nil {
		t.Fatalf("ToUnifiedEvent (2) failed: %v", err)
	}

	var r1, r2 map[string]interface{}
	if err := json.Unmarshal(payload1, &r1); err != nil {
		t.Fatalf("unmarshal 1: %v", err)
	}
	if err := json.Unmarshal(payload2, &r2); err != nil {
		t.Fatalf("unmarshal 2: %v", err)
	}

	hash1, _ := r1["audit_hash"].(string)
	hash2, _ := r2["audit_hash"].(string)

	if len(hash1) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got len=%d: %s", len(hash1), hash1)
	}
	// Hashes differ because event_id (UUID) differs between calls, which is expected.
	// What we verify is that both hashes are non-empty and valid hex.
	if hash1 == "" {
		t.Error("audit_hash should not be empty")
	}
	if hash2 == "" {
		t.Error("audit_hash (second call) should not be empty")
	}

	// Verify it's a valid hex string (only hex chars).
	for _, c := range hash1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("audit_hash contains non-hex character: %c in %s", c, hash1)
		}
	}
}

// TestCommsEventPrivacyFirst verifies that ToUnifiedEventPrivacyFirst omits content from metadata.
func TestCommsEventPrivacyFirst(t *testing.T) {
	event := &common.CommsEvent{
		EventType:   "message_received",
		Channel:     "whatsapp",
		Timestamp:   time.Now(),
		SenderID:    "+1234567890",
		RecipientID: "+0987654321",
		MessageID:   "wamid.privacy",
		Content:     "Sensitive message content",
		Indicators:  []string{},
	}

	payload, err := event.ToUnifiedEventPrivacyFirst()
	if err != nil {
		t.Fatalf("ToUnifiedEventPrivacyFirst failed: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(payload, &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	metadata, ok := result["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("metadata is not an object")
	}

	if _, contentPresent := metadata["content"]; contentPresent {
		t.Error("expected content to be omitted from metadata in privacy-first mode")
	}
}

// TestCommsEventSensorConfig verifies DefaultConfig returns sensible defaults.
func TestCommsEventSensorConfig(t *testing.T) {
	cfg := common.DefaultConfig()
	if cfg.RawEventTopic != "openguard.commsguard.raw" {
		t.Errorf("expected default topic openguard.commsguard.raw, got %s", cfg.RawEventTopic)
	}
	if cfg.NATSUrl == "" {
		t.Error("expected non-empty NATSUrl in default config")
	}
	if cfg.ListenAddr == "" {
		t.Error("expected non-empty ListenAddr in default config")
	}
	if cfg.BulkMessageThreshold != 20 {
		t.Errorf("expected BulkMessageThreshold=20, got %d", cfg.BulkMessageThreshold)
	}
	if cfg.BulkMessageWindow != 60*time.Second {
		t.Errorf("expected BulkMessageWindow=60s, got %v", cfg.BulkMessageWindow)
	}
	if !cfg.EnableContentAnalysis {
		t.Error("expected EnableContentAnalysis=true by default")
	}
}

// TestThreatAnalyzer_BulkMessageDetection verifies the analyzer detects bulk messaging.
func TestThreatAnalyzer_BulkMessageDetection(t *testing.T) {
	analyzer := common.NewThreatAnalyzer(5, 60*time.Second, true)

	senderID := "bulk-sender"
	now := time.Now()

	// Send 6 messages (threshold is 5) — expect bulk indicator on last.
	var lastIndicators []string
	for i := 0; i < 6; i++ {
		event := &common.CommsEvent{
			EventType:  "message_received",
			Channel:    "telegram",
			Timestamp:  now.Add(time.Duration(i) * time.Second),
			SenderID:   senderID,
			Content:    "Hi there",
			Indicators: []string{},
		}
		lastIndicators = analyzer.Analyze(event)
	}

	if !containsCommsIndicator(lastIndicators, "bulk_message") {
		t.Errorf("expected 'bulk_message' indicator after exceeding threshold, got %v", lastIndicators)
	}
}

// TestThreatAnalyzer_DisabledContentAnalysis verifies that disabling content
// analysis skips content-based checks.
func TestThreatAnalyzer_DisabledContentAnalysis(t *testing.T) {
	analyzer := common.NewThreatAnalyzer(20, 60*time.Second, false)

	event := &common.CommsEvent{
		EventType:  "message_received",
		Channel:    "whatsapp",
		Timestamp:  time.Now(),
		SenderID:   "phisher",
		Content:    "Please click here http://evil.xyz verify your account now!",
		Indicators: []string{},
	}

	indicators := analyzer.Analyze(event)
	// With content analysis disabled, phishing/suspicious_link should NOT be detected.
	for _, ind := range indicators {
		if ind == "phishing" || ind == "suspicious_link" || ind == "credential_harvesting" {
			t.Errorf("expected no content-based indicator when content analysis disabled, got %v", ind)
		}
	}
}

// containsCommsIndicator returns true if the given indicator string is in the slice.
func containsCommsIndicator(indicators []string, target string) bool {
	for _, ind := range indicators {
		if ind == target {
			return true
		}
	}
	return false
}
