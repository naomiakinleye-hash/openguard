// Package consoleapi — commsguard.go provides the CommsGuard-specific REST
// API handlers for the console: per-channel statistics, event filtering,
// channel status, and channel configuration management.
package consoleapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// commsChannelDef describes a supported CommsGuard communication channel.
type commsChannelDef struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Icon        string `json:"icon"`
	WebhookPath string `json:"webhook_path"`
	Description string `json:"description"`
}

// commsChannelStatus is the runtime status of a CommsGuard channel.
type commsChannelStatus struct {
	commsChannelDef
	Configured   bool   `json:"configured"`
	MessageCount int    `json:"message_count"`
	ThreatCount  int    `json:"threat_count"`
	LastEvent    string `json:"last_event,omitempty"`
}

// commsEventTypeStat is a count of a specific comms event type.
type commsEventTypeStat struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

// commsStatsResponse is the response body for GET /api/v1/commsguard/stats.
type commsStatsResponse struct {
	Channels     []commsChannelStatus `json:"channels"`
	EventTypes   []commsEventTypeStat `json:"event_types"`
	TotalEvents  int                  `json:"total_events"`
	TotalThreats int                  `json:"total_threats"`
	Period       string               `json:"period"`
	ComputedAt   string               `json:"computed_at"`
}

// commsChannelConfig holds the configurable settings for one CommsGuard channel.
type commsChannelConfig struct {
	Enabled         bool   `json:"enabled"`
	WebhookSecret   string `json:"webhook_secret,omitempty"`
	VerifyToken     string `json:"verify_token,omitempty"`
	AccountSID      string `json:"account_sid,omitempty"`
	BearerToken     string `json:"bearer_token,omitempty"`
	BotToken        string `json:"bot_token,omitempty"`
	WebhookURL      string `json:"webhook_url,omitempty"`
}

// commsConfig holds runtime configuration for all CommsGuard channels.
type commsConfig struct {
	mu              sync.RWMutex
	channels        map[string]*commsChannelConfig
	ContentAnalysis bool `json:"enable_content_analysis"`
	BulkThreshold   int  `json:"bulk_message_threshold"`
	BulkWindowSec   int  `json:"bulk_message_window_sec"`
}

// newCommsConfig returns a commsConfig with defaults.
func newCommsConfig() *commsConfig {
	channels := map[string]*commsChannelConfig{
		"whatsapp":     {Enabled: false},
		"telegram":     {Enabled: false},
		"messenger":    {Enabled: false},
		"twilio_sms":   {Enabled: false},
		"twilio_voice": {Enabled: false},
		"twitter":      {Enabled: false},
	}
	return &commsConfig{
		channels:        channels,
		ContentAnalysis: true,
		BulkThreshold:   20,
		BulkWindowSec:   60,
	}
}

// knownCommsChannels is the ordered list of all supported channels.
var knownCommsChannels = []commsChannelDef{
	{
		ID:          "whatsapp",
		Name:        "WhatsApp Business API",
		Icon:        "💬",
		WebhookPath: "/whatsapp/webhook",
		Description: "Monitors WhatsApp Business messages for phishing, credential harvesting, and malicious attachments.",
	},
	{
		ID:          "telegram",
		Name:        "Telegram Bot API",
		Icon:        "✈️",
		WebhookPath: "/telegram/webhook",
		Description: "Monitors Telegram bot messages for suspicious URLs, forwarded phishing content, and malware attachments.",
	},
	{
		ID:          "messenger",
		Name:        "Facebook Messenger",
		Icon:        "💙",
		WebhookPath: "/messenger/webhook",
		Description: "Monitors Facebook Messenger events for social engineering, phishing attempts, and bulk message campaigns.",
	},
	{
		ID:          "twilio_sms",
		Name:        "Twilio SMS",
		Icon:        "📱",
		WebhookPath: "/twilio/sms",
		Description: "Monitors inbound/outbound SMS traffic for smishing (SMS phishing), credential requests, and spam.",
	},
	{
		ID:          "twilio_voice",
		Name:        "Twilio Voice",
		Icon:        "📞",
		WebhookPath: "/twilio/voice",
		Description: "Monitors voice call metadata for vishing (voice phishing) and social engineering patterns.",
	},
	{
		ID:          "twitter",
		Name:        "Twitter / X",
		Icon:        "🐦",
		WebhookPath: "/twitter/webhook",
		Description: "Monitors direct messages and mentions for phishing links, impersonation, and data exfiltration.",
	},
}

// channelFromAdapter maps event adapter/source names to canonical channel IDs.
var channelFromAdapter = map[string]string{
	"whatsapp":     "whatsapp",
	"telegram":     "telegram",
	"messenger":    "messenger",
	"twilio_sms":   "twilio_sms",
	"twilio_voice": "twilio_voice",
	"twitter":      "twitter",
}

// threatEventTypes is the set of event types that are classified as threats.
var threatEventTypes = map[string]bool{
	"phishing_detected":             true,
	"credential_harvesting_detected": true,
	"data_exfiltration_detected":    true,
	"social_engineering_detected":   true,
	"bulk_message_detected":         true,
	"suspicious_link_detected":      true,
	"malware_attachment_detected":   true,
	"account_takeover_attempt":      true,
	"spam_detected":                 true,
}

// handleCommsGuardStats handles GET /api/v1/commsguard/stats.
// It derives per-channel message and threat counts from the in-memory event store,
// filtering for events in the comms domain.
func (s *Server) handleCommsGuardStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Collect all events (up to 10 000 to bound memory consumption).
	items, total := s.events.List(1, 10000)

	channelMessages := make(map[string]int)
	channelThreats := make(map[string]int)
	channelLastEvent := make(map[string]string)
	eventTypeCounts := make(map[string]int)
	totalComms := 0
	totalThreats := 0

	for _, ev := range items {
		// Filter for comms-domain events only.
		domain, _ := ev["domain"].(string)
		if domain != "comms" {
			continue
		}
		totalComms++

		// Derive the channel from the source adapter field.
		channel := ""
		if src, ok := ev["source"].(map[string]interface{}); ok {
			if adapter, ok := src["adapter"].(string); ok {
				channel = adapter
			}
		}
		// Also check metadata for channel field.
		if channel == "" {
			if meta, ok := ev["metadata"].(map[string]interface{}); ok {
				channel, _ = meta["channel"].(string)
			}
		}

		channelMessages[channel]++

		// Determine event type.
		evType := ""
		if meta, ok := ev["metadata"].(map[string]interface{}); ok {
			evType, _ = meta["event_type"].(string)
		}
		if evType == "" {
			evType, _ = ev["type"].(string)
		}
		if evType != "" {
			eventTypeCounts[evType]++
		}

		// Determine if this is a threat event.
		isThreat := false
		if threatEventTypes[evType] {
			isThreat = true
		}
		// Also consider tier >= 2 as a threat.
		if !isThreat {
			if tier, ok := ev["tier"].(float64); ok && tier >= 2 {
				isThreat = true
			}
		}
		// Check indicators list.
		if !isThreat {
			if indicators, ok := ev["indicators"].([]interface{}); ok && len(indicators) > 0 {
				isThreat = true
			}
		}
		if isThreat {
			channelThreats[channel]++
			totalThreats++
		}

		// Track last event timestamp per channel.
		ts, _ := ev["timestamp"].(string)
		if ts != "" {
			if prev, exists := channelLastEvent[channel]; !exists || ts > prev {
				channelLastEvent[channel] = ts
			}
		}
	}

	_ = total // total across all domains

	// Build per-channel status list.
	cfg := s.commsConfig
	channelStatuses := make([]commsChannelStatus, 0, len(knownCommsChannels))
	for _, def := range knownCommsChannels {
		configured := false
		cfg.mu.RLock()
		if ch, ok := cfg.channels[def.ID]; ok {
			configured = ch.Enabled
		}
		cfg.mu.RUnlock()

		channelStatuses = append(channelStatuses, commsChannelStatus{
			commsChannelDef: def,
			Configured:      configured,
			MessageCount:    channelMessages[def.ID],
			ThreatCount:     channelThreats[def.ID],
			LastEvent:       channelLastEvent[def.ID],
		})
	}

	// Build event-type stats list, sorted by count descending.
	evTypeStats := make([]commsEventTypeStat, 0, len(eventTypeCounts))
	for t, c := range eventTypeCounts {
		evTypeStats = append(evTypeStats, commsEventTypeStat{Type: t, Count: c})
	}
	sortCommsEventTypeStats(evTypeStats)

	resp := commsStatsResponse{
		Channels:     channelStatuses,
		EventTypes:   evTypeStats,
		TotalEvents:  totalComms,
		TotalThreats: totalThreats,
		Period:       "all_time",
		ComputedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	writeJSON(w, http.StatusOK, resp)
}

// sortCommsEventTypeStats sorts in-place by Count descending (insertion sort for small lists).
func sortCommsEventTypeStats(stats []commsEventTypeStat) {
	for i := 1; i < len(stats); i++ {
		key := stats[i]
		j := i - 1
		for j >= 0 && stats[j].Count < key.Count {
			stats[j+1] = stats[j]
			j--
		}
		stats[j+1] = key
	}
}

// handleCommsGuardEvents handles GET /api/v1/commsguard/events.
// Supports optional query params: channel=<id>, page=<n>, page_size=<n>.
func (s *Server) handleCommsGuardEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	channel := q.Get("channel") // optional channel filter
	page := 1
	pageSize := 50

	if p := q.Get("page"); p != "" {
		if n, err := parseInt(p); err == nil && n > 0 {
			page = n
		}
	}
	if ps := q.Get("page_size"); ps != "" {
		if n, err := parseInt(ps); err == nil && n > 0 && n <= 200 {
			pageSize = n
		}
	}

	// Pull all events and filter to comms domain.
	all, _ := s.events.List(1, 10000)
	var commsEvents []map[string]interface{}
	for _, ev := range all {
		domain, _ := ev["domain"].(string)
		if domain != "comms" {
			continue
		}
		// Optional channel filter.
		if channel != "" {
			evChannel := extractCommsChannel(ev)
			if evChannel != channel {
				continue
			}
		}
		commsEvents = append(commsEvents, ev)
	}

	total := len(commsEvents)
	// Apply pagination.
	start := (page - 1) * pageSize
	if start >= total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	page_items := commsEvents[start:end]
	if page_items == nil {
		page_items = []map[string]interface{}{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events":    page_items,
		"page":      page,
		"page_size": pageSize,
		"total":     total,
	})
}

// handleCommsGuardChannels handles GET /api/v1/commsguard/channels.
// Returns the list of supported channels with their configuration status.
func (s *Server) handleCommsGuardChannels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := s.commsConfig
	type channelResp struct {
		commsChannelDef
		Configured bool `json:"configured"`
		Enabled    bool `json:"enabled"`
	}
	channels := make([]channelResp, 0, len(knownCommsChannels))
	for _, def := range knownCommsChannels {
		configured := false
		enabled := false
		cfg.mu.RLock()
		if ch, ok := cfg.channels[def.ID]; ok {
			enabled = ch.Enabled
			// A channel is "configured" if the Enabled flag is set or if any
			// credential field is non-empty.
			configured = ch.Enabled || ch.WebhookSecret != "" || ch.BotToken != "" || ch.BearerToken != ""
		}
		cfg.mu.RUnlock()

		channels = append(channels, channelResp{
			commsChannelDef: def,
			Configured:      configured,
			Enabled:         enabled,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"channels": channels})
}

// handleCommsGuardConfig handles GET and PUT /api/v1/commsguard/config.
// GET returns current configuration (credentials are redacted).
// PUT accepts a partial JSON update and merges it.
func (s *Server) handleCommsGuardConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.commsConfig

	switch r.Method {
	case http.MethodGet:
		cfg.mu.RLock()
		defer cfg.mu.RUnlock()

		type channelConfigResp struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
			// Credentials are redacted in GET responses.
			HasWebhookSecret bool `json:"has_webhook_secret"`
			HasVerifyToken   bool `json:"has_verify_token"`
			HasAccountSID    bool `json:"has_account_sid"`
			HasBearerToken   bool `json:"has_bearer_token"`
			HasBotToken      bool `json:"has_bot_token"`
			WebhookURL       string `json:"webhook_url,omitempty"`
		}

		channels := make([]channelConfigResp, 0, len(knownCommsChannels))
		for _, def := range knownCommsChannels {
			ch := cfg.channels[def.ID]
			resp := channelConfigResp{ID: def.ID}
			if ch != nil {
				resp.Enabled = ch.Enabled
				resp.HasWebhookSecret = ch.WebhookSecret != ""
				resp.HasVerifyToken = ch.VerifyToken != ""
				resp.HasAccountSID = ch.AccountSID != ""
				resp.HasBearerToken = ch.BearerToken != ""
				resp.HasBotToken = ch.BotToken != ""
				resp.WebhookURL = ch.WebhookURL
			}
			channels = append(channels, resp)
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"channels":                   channels,
			"enable_content_analysis":    cfg.ContentAnalysis,
			"bulk_message_threshold":     cfg.BulkThreshold,
			"bulk_message_window_sec":    cfg.BulkWindowSec,
		})

	case http.MethodPut:
		var body struct {
			Channel struct {
				ID             string `json:"id"`
				Enabled        bool   `json:"enabled"`
				WebhookSecret  string `json:"webhook_secret"`
				VerifyToken    string `json:"verify_token"`
				AccountSID     string `json:"account_sid"`
				BearerToken    string `json:"bearer_token"`
				BotToken       string `json:"bot_token"`
				WebhookURL     string `json:"webhook_url"`
			} `json:"channel"`
			EnableContentAnalysis *bool `json:"enable_content_analysis"`
			BulkThreshold         *int  `json:"bulk_message_threshold"`
			BulkWindowSec         *int  `json:"bulk_message_window_sec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		cfg.mu.Lock()
		if body.Channel.ID != "" {
			ch, ok := cfg.channels[body.Channel.ID]
			if !ok {
				cfg.mu.Unlock()
				http.Error(w, "unknown channel id", http.StatusBadRequest)
				return
			}
			ch.Enabled = body.Channel.Enabled
			if body.Channel.WebhookSecret != "" {
				ch.WebhookSecret = body.Channel.WebhookSecret
			}
			if body.Channel.VerifyToken != "" {
				ch.VerifyToken = body.Channel.VerifyToken
			}
			if body.Channel.AccountSID != "" {
				ch.AccountSID = body.Channel.AccountSID
			}
			if body.Channel.BearerToken != "" {
				ch.BearerToken = body.Channel.BearerToken
			}
			if body.Channel.BotToken != "" {
				ch.BotToken = body.Channel.BotToken
			}
			if body.Channel.WebhookURL != "" {
				ch.WebhookURL = body.Channel.WebhookURL
			}
		}
		if body.EnableContentAnalysis != nil {
			cfg.ContentAnalysis = *body.EnableContentAnalysis
		}
		if body.BulkThreshold != nil {
			cfg.BulkThreshold = *body.BulkThreshold
		}
		if body.BulkWindowSec != nil {
			cfg.BulkWindowSec = *body.BulkWindowSec
		}
		cfg.mu.Unlock()

		writeJSON(w, http.StatusOK, map[string]interface{}{"status": "ok"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// extractCommsChannel returns the channel identifier from an event map.
func extractCommsChannel(ev map[string]interface{}) string {
	if src, ok := ev["source"].(map[string]interface{}); ok {
		if adapter, ok := src["adapter"].(string); ok && adapter != "" {
			return adapter
		}
	}
	if meta, ok := ev["metadata"].(map[string]interface{}); ok {
		if ch, ok := meta["channel"].(string); ok {
			return ch
		}
	}
	return ""
}

// parseInt parses a string to int, returning an error for non-integer strings.
func parseInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	n := 0
	if len(s) == 0 {
		return 0, &parseError{s}
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, &parseError{s}
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

type parseError struct{ s string }

func (e *parseError) Error() string { return "not an integer: " + e.s }
