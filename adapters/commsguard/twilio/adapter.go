// Package twilio implements the CommsGuard Twilio SMS and Voice adapter.
// It refactors the original twilio adapter into the CommsGuard architecture,
// integrating ThreatAnalyzer and publishing CommsEvents to NATS.
package twilio

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // Twilio requires SHA-1 for request validation
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	"go.uber.org/zap"
)

// TwilioAdapter implements common.Sensor for Twilio SMS and Voice.
type TwilioAdapter struct {
	authToken          string
	accountSID         string
	tollFraudThreshold int
	publisher          *common.Publisher
	analyzer           *common.ThreatAnalyzer
	logger             *zap.Logger

	mu      sync.Mutex
	running bool
}

// NewTwilioAdapter constructs a new TwilioAdapter.
func NewTwilioAdapter(authToken, accountSID string, publisher *common.Publisher, analyzer *common.ThreatAnalyzer, logger *zap.Logger) *TwilioAdapter {
	return &TwilioAdapter{
		authToken:          authToken,
		accountSID:         accountSID,
		tollFraudThreshold: 50,
		publisher:          publisher,
		analyzer:           analyzer,
		logger:             logger,
	}
}

// Start marks the adapter as running.
func (a *TwilioAdapter) Start(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = true
	return nil
}

// Stop marks the adapter as stopped.
func (a *TwilioAdapter) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.running = false
	return nil
}

// Channel returns the channel identifier.
func (a *TwilioAdapter) Channel() string { return "twilio" }

// HealthCheck returns nil if the adapter is running.
func (a *TwilioAdapter) HealthCheck(_ context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		return fmt.Errorf("twilio adapter is not running")
	}
	return nil
}

// HandleSMS is the HTTP handler for Twilio SMS webhook POST requests.
func (a *TwilioAdapter) HandleSMS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := a.validateSignature(r); err != nil {
		a.logger.Warn("twilio: SMS signature validation failed", zap.Error(err))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	params := urlValuesToMap(r.PostForm)
	event := a.normalizeSMS(params)

	indicators := a.analyzer.Analyze(event)
	if len(indicators) > 0 {
		event.Indicators = append(event.Indicators, indicators...)
		event.EventType = promoteEventType(event.EventType, indicators)
	}

	if err := a.publisher.Publish(r.Context(), event); err != nil {
		a.logger.Error("twilio: publish SMS failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// HandleVoice is the HTTP handler for Twilio Voice webhook POST requests.
func (a *TwilioAdapter) HandleVoice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := a.validateSignature(r); err != nil {
		a.logger.Warn("twilio: Voice signature validation failed", zap.Error(err))
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	params := urlValuesToMap(r.PostForm)
	event := a.normalizeVoice(params)

	// Run threat analysis on voice metadata (caller ID, destination, bulk call patterns).
	// Voice events have no body text, but bulk/toll-fraud indicators are metadata-driven.
	indicators := a.analyzer.Analyze(event)
	if len(indicators) > 0 {
		event.Indicators = append(event.Indicators, indicators...)
		event.EventType = promoteEventType(event.EventType, indicators)
	}

	if err := a.publisher.Publish(r.Context(), event); err != nil {
		a.logger.Error("twilio: publish Voice failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// normalizeSMS converts Twilio SMS webhook parameters to a CommsEvent.
func (a *TwilioAdapter) normalizeSMS(params map[string]string) *common.CommsEvent {
	msgSID := params["MessageSid"]
	if msgSID == "" {
		msgSID = fmt.Sprintf("sms-%d", time.Now().UnixNano())
	}
	from := params["From"]
	to := params["To"]
	body := params["Body"]

	rawData := make(map[string]interface{}, len(params))
	for k, v := range params {
		rawData[k] = v
	}

	return &common.CommsEvent{
		EventType:   "message_received",
		Channel:     "twilio_sms",
		Timestamp:   time.Now().UTC(),
		SenderID:    from,
		RecipientID: to,
		MessageID:   msgSID,
		Content:     body,
		Indicators:  []string{},
		RawData:     rawData,
	}
}

// normalizeVoice converts Twilio Voice webhook parameters to a CommsEvent.
func (a *TwilioAdapter) normalizeVoice(params map[string]string) *common.CommsEvent {
	callSID := params["CallSid"]
	if callSID == "" {
		callSID = fmt.Sprintf("voice-%d", time.Now().UnixNano())
	}
	from := params["From"]
	to := params["To"]

	rawData := make(map[string]interface{}, len(params))
	for k, v := range params {
		rawData[k] = v
	}

	indicators := []string{}
	// Toll fraud detection hook: flag calls to premium-rate number ranges.
	if isTollFraudIndicator(to) {
		indicators = append(indicators, "toll_fraud")
	}

	return &common.CommsEvent{
		EventType:   "message_received",
		Channel:     "twilio_voice",
		Timestamp:   time.Now().UTC(),
		SenderID:    from,
		RecipientID: to,
		MessageID:   callSID,
		Indicators:  indicators,
		RawData:     rawData,
	}
}

// validateSignature verifies the Twilio X-Twilio-Signature header.
func (a *TwilioAdapter) validateSignature(r *http.Request) error {
	if a.authToken == "" {
		return nil // disabled in dev mode
	}
	sig := r.Header.Get("X-Twilio-Signature")
	if sig == "" {
		return fmt.Errorf("twilio: missing X-Twilio-Signature header")
	}

	// Build the string to sign: URL + sorted POST params + values.
	reqURL := fmt.Sprintf("https://%s%s", r.Host, r.URL.RequestURI())
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("twilio: parse form: %w", err)
	}
	keys := make([]string, 0, len(r.PostForm))
	for k := range r.PostForm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(reqURL)
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(r.PostForm.Get(k))
	}

	mac := hmac.New(sha1.New, []byte(a.authToken)) //nolint:gosec
	mac.Write([]byte(sb.String()))                  //nolint:errcheck
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("twilio: signature mismatch")
	}
	return nil
}

// isTollFraudIndicator returns true if the phone number matches known toll fraud patterns.
func isTollFraudIndicator(number string) bool {
	fraudPrefixes := []string{"+1900", "+0900", "+44909"}
	for _, prefix := range fraudPrefixes {
		if strings.HasPrefix(number, prefix) {
			return true
		}
	}
	return false
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

// urlValuesToMap converts url.Values to map[string]string using the first value per key.
func urlValuesToMap(form url.Values) map[string]string {
	out := make(map[string]string, len(form))
	for k, vals := range form {
		if len(vals) > 0 {
			out[k] = vals[0]
		}
	}
	return out
}
