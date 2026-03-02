// Package commsguardcommon provides shared types and utilities for the CommsGuard sensor.
package commsguardcommon

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CommsEvent is the raw communications sensor event before normalization.
type CommsEvent struct {
	EventType   string // message_received, message_sent, phishing_detected,
	// credential_harvesting_detected, data_exfiltration_detected,
	// social_engineering_detected, bulk_message_detected,
	// suspicious_link_detected, malware_attachment_detected,
	// account_takeover_attempt, spam_detected, unknown_sender
	Channel     string    // "whatsapp", "telegram", "messenger", "twilio_sms", "twilio_voice", "twitter"
	Timestamp   time.Time
	SenderID    string // phone number, user ID, username, or account handle
	RecipientID string // phone number, chat ID, user ID, or channel ID
	MessageID   string // platform-specific message ID
	Content     string // message text (may be empty if privacy-first mode)
	Indicators  []string
	RawData     map[string]interface{}
}

// ToUnifiedEvent converts a CommsEvent to the UnifiedEvent JSON format
// compatible with the ingest service schema (schemas/unified-event.schema.json).
// It generates a UUID event_id, computes a basic audit_hash (SHA-256 of payload),
// and sets domain="comms", human_approved=false.
func (e *CommsEvent) ToUnifiedEvent() ([]byte, error) {
	return e.toUnifiedEventInternal(true)
}

// ToUnifiedEventPrivacyFirst converts a CommsEvent omitting message Content
// from metadata, for privacy-first deployments.
func (e *CommsEvent) ToUnifiedEventPrivacyFirst() ([]byte, error) {
	return e.toUnifiedEventInternal(false)
}

func (e *CommsEvent) toUnifiedEventInternal(includeContent bool) ([]byte, error) {
	severity, riskScore, tier := classifyEvent(e)

	metadata := map[string]interface{}{
		"event_type":   e.EventType,
		"channel":      e.Channel,
		"sender_id":    e.SenderID,
		"recipient_id": e.RecipientID,
		"message_id":   e.MessageID,
	}
	if includeContent && e.Content != "" {
		metadata["content"] = e.Content
	}
	for k, v := range e.RawData {
		metadata[k] = v
	}

	indicators := e.Indicators
	if indicators == nil {
		indicators = []string{}
	}

	intermediate := map[string]interface{}{
		"event_id":  uuid.New().String(),
		"timestamp": e.Timestamp.UTC().Format(time.RFC3339),
		"source": map[string]interface{}{
			"type":    "comms",
			"adapter": e.Channel,
		},
		"domain":    "comms",
		"severity":  severity,
		"risk_score": riskScore,
		"tier":      tier,
		"actor": map[string]interface{}{
			"id":   e.SenderID,
			"type": "user",
		},
		"target": map[string]interface{}{
			"id":   e.RecipientID,
			"type": "user",
		},
		"indicators":       indicators,
		"policy_citations": []string{},
		"human_approved":   false,
		"audit_hash":       "",
		"metadata":         metadata,
	}

	// First marshal without audit_hash to compute hash.
	intermediate["audit_hash"] = ""
	partial, err := json.Marshal(intermediate)
	if err != nil {
		return nil, fmt.Errorf("commsguard: marshal partial event: %w", err)
	}

	hash := sha256.Sum256(partial)
	intermediate["audit_hash"] = fmt.Sprintf("%x", hash)

	payload, err := json.Marshal(intermediate)
	if err != nil {
		return nil, fmt.Errorf("commsguard: marshal unified event: %w", err)
	}
	return payload, nil
}

// classifyEvent assigns severity, risk_score, and tier based on event type and indicators.
func classifyEvent(e *CommsEvent) (severity string, riskScore float64, tier string) {
	// Indicator special-cases take priority over event type.
	for _, ind := range e.Indicators {
		switch ind {
		case "credential_harvesting":
			return "critical", 92.0, "immediate"
		case "data_exfiltration":
			return "critical", 95.0, "immediate"
		case "malware_attachment":
			return "critical", 95.0, "immediate"
		case "account_takeover":
			return "critical", 88.0, "immediate"
		}
	}
	switch e.EventType {
	case "message_received", "message_sent":
		return "info", 5.0, "T0"
	case "phishing_detected":
		return "high", 75.0, "T2"
	case "credential_harvesting_detected":
		return "critical", 90.0, "immediate"
	case "data_exfiltration_detected":
		return "critical", 92.0, "immediate"
	case "social_engineering_detected":
		return "high", 70.0, "T2"
	case "bulk_message_detected":
		return "high", 65.0, "T2"
	case "suspicious_link_detected":
		return "medium", 50.0, "T2"
	case "malware_attachment_detected":
		return "critical", 95.0, "immediate"
	case "account_takeover_attempt":
		return "critical", 88.0, "immediate"
	case "spam_detected":
		return "low", 20.0, "T1"
	case "unknown_sender":
		return "low", 15.0, "T0"
	default:
		return "low", 20.0, "T1"
	}
}
