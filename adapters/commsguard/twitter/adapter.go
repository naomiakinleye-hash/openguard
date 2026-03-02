// Package twitter implements the CommsGuard Twitter/X Account Activity API adapter.
// It handles CRC challenges, signature verification, and normalization of
// tweet and direct message events to CommsEvent format for NATS publishing.
package twitter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	"go.uber.org/zap"
)

// TwitterAdapter implements common.Sensor for the Twitter/X Account Activity API.
type TwitterAdapter struct {
	webhookSecret string
	bearerToken   string
	publisher     *common.Publisher
	analyzer      *common.ThreatAnalyzer
	logger        *zap.Logger

	mu            sync.Mutex
	running       bool
	followTracker *followTracker
}

// followTracker tracks follow events for bulk detection.
type followTracker struct {
	mu         sync.Mutex
	timestamps []time.Time
}

func (ft *followTracker) record(ts time.Time) int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.timestamps = append(ft.timestamps, ts)
	cutoff := ts.Add(-time.Hour)
	pruned := ft.timestamps[:0]
	for _, t := range ft.timestamps {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	ft.timestamps = pruned
	return len(ft.timestamps)
}

// NewTwitterAdapter constructs a new TwitterAdapter.
func NewTwitterAdapter(webhookSecret, bearerToken string, publisher *common.Publisher, analyzer *common.ThreatAnalyzer, logger *zap.Logger) *TwitterAdapter {
	return &TwitterAdapter{
		webhookSecret: webhookSecret,
		bearerToken:   bearerToken,
		publisher:     publisher,
		analyzer:      analyzer,
		logger:        logger,
		followTracker: &followTracker{},
	}
}

// Start marks the adapter as running.
func (a *TwitterAdapter) Start(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = true
	return nil
}

// Stop marks the adapter as stopped.
func (a *TwitterAdapter) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = false
	return nil
}

// Channel returns the channel identifier.
func (a *TwitterAdapter) Channel() string { return "twitter" }

// HealthCheck returns nil if the adapter is running.
func (a *TwitterAdapter) HealthCheck(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return fmt.Errorf("twitter adapter is not running")
	}
	return nil
}

// ServeHTTP handles incoming Twitter webhook requests.
func (a *TwitterAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// CRC challenge.
		a.handleCRC(w, r)
	case http.MethodPost:
		a.handleActivity(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCRC responds to the Twitter CRC challenge.
func (a *TwitterAdapter) handleCRC(w http.ResponseWriter, r *http.Request) {
	crcToken := r.URL.Query().Get("crc_token")
	if crcToken == "" {
		http.Error(w, "missing crc_token", http.StatusBadRequest)
		return
	}
	mac := hmac.New(sha256.New, []byte(a.webhookSecret))
	mac.Write([]byte(crcToken)) //nolint:errcheck
	responseToken := "sha256=" + base64.StdEncoding.EncodeToString(mac.Sum(nil))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"response_token": responseToken}) //nolint:errcheck
}

// handleActivity processes Twitter Account Activity API webhook events.
func (a *TwitterAdapter) handleActivity(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Verify signature.
	sig := r.Header.Get("X-Twitter-Webhooks-Signature")
	if err := a.verifySignature(body, sig); err != nil {
		a.logger.Warn("twitter: signature verification failed", zap.Error(err))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var activity map[string]interface{}
	if err := json.Unmarshal(body, &activity); err != nil {
		a.logger.Warn("twitter: invalid JSON payload", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	events := a.normalizeActivity(activity)
	for _, event := range events {
		indicators := a.analyzer.Analyze(event)
		if len(indicators) > 0 {
			event.Indicators = append(event.Indicators, indicators...)
			event.EventType = promoteEventType(event.EventType, indicators)
		}

		if err := a.publisher.Publish(r.Context(), event); err != nil {
			a.logger.Error("twitter: publish failed", zap.Error(err))
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

// normalizeActivity converts a Twitter activity payload to one or more CommsEvents.
func (a *TwitterAdapter) normalizeActivity(activity map[string]interface{}) []*common.CommsEvent {
	var events []*common.CommsEvent

	// Handle direct_message_events.
	if dmEvents, ok := activity["direct_message_events"].([]interface{}); ok {
		for _, dm := range dmEvents {
			if dmMap, ok := dm.(map[string]interface{}); ok {
				event := a.normalizeDM(dmMap, activity)
				if event != nil {
					events = append(events, event)
				}
			}
		}
	}

	// Handle tweet_create_events.
	if tweetEvents, ok := activity["tweet_create_events"].([]interface{}); ok {
		for _, tw := range tweetEvents {
			if twMap, ok := tw.(map[string]interface{}); ok {
				event := a.normalizeTweet(twMap)
				if event != nil {
					events = append(events, event)
				}
			}
		}
	}

	// Handle follow_events.
	if followEvents, ok := activity["follow_events"].([]interface{}); ok {
		for _, fe := range followEvents {
			if feMap, ok := fe.(map[string]interface{}); ok {
				event := a.normalizeFollow(feMap)
				if event != nil {
					events = append(events, event)
				}
			}
		}
	}

	return events
}

// normalizeDM converts a Twitter DM event to a CommsEvent.
func (a *TwitterAdapter) normalizeDM(dm map[string]interface{}, activity map[string]interface{}) *common.CommsEvent {
	msgID := ""
	senderID := ""
	recipientID := ""
	content := ""

	if id, ok := dm["id"].(string); ok {
		msgID = id
	} else {
		msgID = fmt.Sprintf("tw-dm-%d", time.Now().UnixNano())
	}

	if msgCreate, ok := dm["message_create"].(map[string]interface{}); ok {
		if sender, ok := msgCreate["sender_id"].(string); ok {
			senderID = sender
		}
		if target, ok := msgCreate["target"].(map[string]interface{}); ok {
			if rID, ok := target["recipient_id"].(string); ok {
				recipientID = rID
			}
		}
		if msgData, ok := msgCreate["message_data"].(map[string]interface{}); ok {
			if text, ok := msgData["text"].(string); ok {
				content = text
			}
		}
	}

	// Resolve sender screen name from users map.
	if senderID != "" {
		if users, ok := activity["users"].(map[string]interface{}); ok {
			if userMap, ok := users[senderID].(map[string]interface{}); ok {
				if screenName, ok := userMap["screen_name"].(string); ok {
					senderID = screenName
				}
			}
		}
	}

	return &common.CommsEvent{
		EventType:   "message_received",
		Channel:     "twitter",
		Timestamp:   time.Now().UTC(),
		SenderID:    senderID,
		RecipientID: recipientID,
		MessageID:   msgID,
		Content:     content,
		Indicators:  []string{},
		RawData:     dm,
	}
}

// normalizeTweet converts a tweet event to a CommsEvent.
func (a *TwitterAdapter) normalizeTweet(tweet map[string]interface{}) *common.CommsEvent {
	msgID := ""
	senderID := ""
	recipientID := ""
	content := ""

	if id, ok := tweet["id_str"].(string); ok {
		msgID = id
	} else {
		msgID = fmt.Sprintf("tw-%d", time.Now().UnixNano())
	}

	if user, ok := tweet["user"].(map[string]interface{}); ok {
		if screenName, ok := user["screen_name"].(string); ok {
			senderID = screenName
		}
	}

	if text, ok := tweet["text"].(string); ok {
		content = text
	}
	if fullText, ok := tweet["full_text"].(string); ok {
		content = fullText
	}

	// Extract mentioned users.
	if entities, ok := tweet["entities"].(map[string]interface{}); ok {
		if mentions, ok := entities["user_mentions"].([]interface{}); ok && len(mentions) > 0 {
			if mention, ok := mentions[0].(map[string]interface{}); ok {
				if screenName, ok := mention["screen_name"].(string); ok {
					recipientID = screenName
				}
			}
		}
	}

	return &common.CommsEvent{
		EventType:   "message_received",
		Channel:     "twitter",
		Timestamp:   time.Now().UTC(),
		SenderID:    senderID,
		RecipientID: recipientID,
		MessageID:   msgID,
		Content:     content,
		Indicators:  []string{},
		RawData:     tweet,
	}
}

// normalizeFollow converts a follow event to a CommsEvent.
func (a *TwitterAdapter) normalizeFollow(fe map[string]interface{}) *common.CommsEvent {
	senderID := ""

	if source, ok := fe["source"].(map[string]interface{}); ok {
		if screenName, ok := source["screen_name"].(string); ok {
			senderID = screenName
		} else if id, ok := source["id"].(string); ok {
			senderID = id
		}
	}

	msgID := fmt.Sprintf("tw-follow-%d", time.Now().UnixNano())
	indicators := []string{}

	// Check for high-volume follow activity (>50 follows/hour).
	count := a.followTracker.record(time.Now())
	if count > 50 {
		indicators = append(indicators, "bulk_message", "follow_flood")
	}

	return &common.CommsEvent{
		EventType:  "unknown_sender",
		Channel:    "twitter",
		Timestamp:  time.Now().UTC(),
		SenderID:   senderID,
		MessageID:  msgID,
		Indicators: indicators,
		RawData:    fe,
	}
}

// verifySignature checks the X-Twitter-Webhooks-Signature header.
// Twitter uses HMAC-SHA256 of raw body, base64-encoded, prefixed with "sha256=".
func (a *TwitterAdapter) verifySignature(body []byte, sig string) error {
	if a.webhookSecret == "" {
		return nil // disabled in dev mode
	}
	if sig == "" {
		return fmt.Errorf("twitter: missing X-Twitter-Webhooks-Signature header")
	}
	if !strings.HasPrefix(sig, "sha256=") {
		return fmt.Errorf("twitter: unexpected signature format")
	}
	mac := hmac.New(sha256.New, []byte(a.webhookSecret))
	mac.Write(body) //nolint:errcheck
	expected := "sha256=" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("twitter: signature mismatch")
	}
	return nil
}

// promoteEventType upgrades the event type based on detected indicators.
func promoteEventType(current string, indicators []string) string {
	for _, ind := range indicators {
		switch ind {
		case "malware_attachment":
			return "malware_attachment_detected"
		case "credential_harvesting":
			return "credential_harvesting_detected"
		case "data_exfiltration":
			return "data_exfiltration_detected"
		case "account_takeover":
			return "account_takeover_attempt"
		case "phishing":
			return "phishing_detected"
		case "social_engineering":
			return "social_engineering_detected"
		case "suspicious_link":
			return "suspicious_link_detected"
		case "bulk_message":
			return "bulk_message_detected"
		case "spam":
			return "spam_detected"
		}
	}
	return current
}
