// Package twilio implements the OpenGuard v5 Twilio SMS and Voice adapter.
// It handles Twilio request signature validation, SMS and Voice webhook
// normalization to UnifiedEvent format, and toll-fraud detection hooks.
package twilio

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // Twilio requires SHA-1 for request validation
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Config holds configuration for the Twilio Adapter.
type Config struct {
	// AuthToken is the Twilio Auth Token used for request signature validation.
	AuthToken string
	// AccountSID is the Twilio Account SID.
	AccountSID string
	// TollFraudThreshold is the maximum number of outbound calls per hour before
	// a toll fraud alert is raised (default: 50).
	TollFraudThreshold int
}

// UnifiedEvent is a normalized event (shared with other adapters in production).
type UnifiedEvent struct {
	EventID       string                 `json:"event_id"`
	Timestamp     time.Time              `json:"timestamp"`
	Source        map[string]interface{} `json:"source"`
	Domain        string                 `json:"domain"`
	Severity      string                 `json:"severity"`
	RiskScore     float64                `json:"risk_score"`
	Tier          string                 `json:"tier"`
	Actor         map[string]interface{} `json:"actor"`
	Target        map[string]interface{} `json:"target"`
	Indicators    []interface{}          `json:"indicators"`
	HumanApproved bool                   `json:"human_approved"`
	AuditHash     string                 `json:"audit_hash"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// EventSink receives normalized events.
type EventSink interface {
	Ingest(ctx context.Context, payload []byte) error
}

// Adapter is the Twilio SMS and Voice adapter.
type Adapter struct {
	cfg    Config
	sink   EventSink
	logger *zap.Logger
}

// NewAdapter constructs a new Twilio Adapter.
func NewAdapter(cfg Config, sink EventSink, logger *zap.Logger) *Adapter {
	if cfg.TollFraudThreshold == 0 {
		cfg.TollFraudThreshold = 50
	}
	return &Adapter{cfg: cfg, sink: sink, logger: logger}
}

// HandleSMS is the HTTP handler for Twilio SMS webhook POST requests.
func (a *Adapter) HandleSMS(w http.ResponseWriter, r *http.Request) {
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
	event, err := a.normalizeSMS(params)
	if err != nil {
		a.logger.Warn("twilio: SMS normalization failed", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	a.ingestEvent(r.Context(), w, event)
}

// HandleVoice is the HTTP handler for Twilio Voice webhook POST requests.
func (a *Adapter) HandleVoice(w http.ResponseWriter, r *http.Request) {
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
	event, err := a.normalizeVoice(params)
	if err != nil {
		a.logger.Warn("twilio: Voice normalization failed", zap.Error(err))
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	a.ingestEvent(r.Context(), w, event)
}

// normalizeSMS converts Twilio SMS webhook parameters to a UnifiedEvent.
func (a *Adapter) normalizeSMS(params map[string]string) (*UnifiedEvent, error) {
	msgSID := params["MessageSid"]
	if msgSID == "" {
		msgSID = fmt.Sprintf("sms-%d", time.Now().UnixNano())
	}
	from := params["From"]
	to := params["To"]

	return &UnifiedEvent{
		EventID:   msgSID,
		Timestamp: time.Now().UTC(),
		Source: map[string]interface{}{
			"type":    "twilio-sms",
			"adapter": "twilio",
		},
		Domain:   "comms",
		Severity: "info",
		Tier:     "T0",
		Actor: map[string]interface{}{
			"id":   from,
			"type": "human",
		},
		Target: map[string]interface{}{
			"id":   to,
			"type": "phone_number",
		},
		Indicators:    []interface{}{},
		HumanApproved: false,
		AuditHash:     "",
		Metadata:      toInterfaceMap(params),
	}, nil
}

// normalizeVoice converts Twilio Voice webhook parameters to a UnifiedEvent.
func (a *Adapter) normalizeVoice(params map[string]string) (*UnifiedEvent, error) {
	callSID := params["CallSid"]
	if callSID == "" {
		callSID = fmt.Sprintf("voice-%d", time.Now().UnixNano())
	}
	from := params["From"]
	to := params["To"]

	indicators := []interface{}{}
	// Toll fraud detection hook: flag calls to premium-rate number ranges.
	if a.isTollFraudIndicator(to) {
		indicators = append(indicators, map[string]interface{}{
			"type":       "toll_fraud",
			"value":      to,
			"confidence": 0.8,
		})
	}

	return &UnifiedEvent{
		EventID:   callSID,
		Timestamp: time.Now().UTC(),
		Source: map[string]interface{}{
			"type":    "twilio-voice",
			"adapter": "twilio",
		},
		Domain:   "comms",
		Severity: func() string {
			if len(indicators) > 0 {
				return "medium"
			}
			return "info"
		}(),
		Tier: func() string {
			if len(indicators) > 0 {
				return "T2"
			}
			return "T0"
		}(),
		Actor: map[string]interface{}{
			"id":   from,
			"type": "human",
		},
		Target: map[string]interface{}{
			"id":   to,
			"type": "phone_number",
		},
		Indicators:    indicators,
		HumanApproved: false,
		AuditHash:     "",
		Metadata:      toInterfaceMap(params),
	}, nil
}

// validateSignature verifies the Twilio X-Twilio-Signature header.
func (a *Adapter) validateSignature(r *http.Request) error {
	if a.cfg.AuthToken == "" {
		return nil // disabled in dev mode
	}
	sig := r.Header.Get("X-Twilio-Signature")
	if sig == "" {
		return fmt.Errorf("twilio: missing X-Twilio-Signature header")
	}

	// Build the string to sign: URL + sorted POST params + values.
	url := fmt.Sprintf("https://%s%s", r.Host, r.URL.RequestURI())
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("twilio: parse form: %w", err)
	}
	keys := make([]string, 0, len(r.PostForm))
	for k := range r.PostForm {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString(url)
	for _, k := range keys {
		sb.WriteString(k)
		sb.WriteString(r.PostForm.Get(k))
	}

	mac := hmac.New(sha1.New, []byte(a.cfg.AuthToken)) //nolint:gosec
	mac.Write([]byte(sb.String()))                      //nolint:errcheck
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return fmt.Errorf("twilio: signature mismatch")
	}
	return nil
}

// isTollFraudIndicator returns true if the phone number matches known toll fraud patterns.
func (a *Adapter) isTollFraudIndicator(number string) bool {
	// Simplified: flag known premium-rate prefixes.
	fraudPrefixes := []string{"+1900", "+0900", "+44909"}
	for _, prefix := range fraudPrefixes {
		if strings.HasPrefix(number, prefix) {
			return true
		}
	}
	return false
}

// ingestEvent marshals and ingests a UnifiedEvent, writing the HTTP response.
func (a *Adapter) ingestEvent(ctx context.Context, w http.ResponseWriter, event *UnifiedEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		a.logger.Error("twilio: marshal unified event", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if err := a.sink.Ingest(ctx, data); err != nil {
		a.logger.Error("twilio: ingest failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
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

// toInterfaceMap converts map[string]string to map[string]interface{}.
func toInterfaceMap(m map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
