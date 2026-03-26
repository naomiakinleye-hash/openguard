// Package consoleapi — webhooks.go provides a configurable outbound webhook
// dispatcher for T1+ incident alerting (Slack, PagerDuty, generic JSON).
package consoleapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// webhookFormat identifies the payload shape sent to a webhook destination.
type webhookFormat string

const (
	WebhookFormatSlack     webhookFormat = "slack"
	WebhookFormatPagerDuty webhookFormat = "pagerduty"
	WebhookFormatGeneric   webhookFormat = "generic"
)

// webhookConfig describes one outbound webhook destination.
type webhookConfig struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	URL       string        `json:"url"`
	MinTier   int           `json:"min_tier"` // 0=T0, 1=T1, 2=T2, 3=T3, 4=T4
	Format    webhookFormat `json:"format"`
	Enabled   bool          `json:"enabled"`
	CreatedAt string        `json:"created_at"`
}

// webhookStore holds the runtime webhook configuration.
type webhookStore struct {
	mu       sync.RWMutex
	webhooks map[string]*webhookConfig
}

func newWebhookStore() *webhookStore {
	return &webhookStore{webhooks: make(map[string]*webhookConfig)}
}

// DispatchWebhooksForIncident fires all enabled webhooks whose MinTier <= incident.Tier.
func (s *Server) DispatchWebhooksForIncident(inc *Incident) {
	s.whStore.mu.RLock()
	targets := make([]*webhookConfig, 0, len(s.whStore.webhooks))
	for _, wh := range s.whStore.webhooks {
		if wh.Enabled && wh.MinTier <= inc.Tier {
			targets = append(targets, wh)
		}
	}
	s.whStore.mu.RUnlock()

	for _, wh := range targets {
		go s.fireWebhook(wh, inc)
	}
}

func (s *Server) fireWebhook(wh *webhookConfig, inc *Incident) {
	var payload interface{}
	switch wh.Format {
	case WebhookFormatSlack:
		payload = map[string]interface{}{
			"text": fmt.Sprintf(
				"🚨 *OpenGuard Alert* — Incident `%s`\n*Tier:* T%d | *Risk:* %.0f | *Status:* %s\n*Description:* %s",
				inc.ID, inc.Tier, inc.RiskScore, inc.Status, inc.Description,
			),
		}
	case WebhookFormatPagerDuty:
		payload = map[string]interface{}{
			"event_action": "trigger",
			"payload": map[string]interface{}{
				"summary":  fmt.Sprintf("OpenGuard T%d: %s", inc.Tier, inc.Description),
				"severity": webhookSeverity(inc.Tier),
				"source":   "openguard",
				"custom_details": map[string]interface{}{
					"incident_id": inc.ID,
					"risk_score":  inc.RiskScore,
					"type":        inc.Type,
				},
			},
		}
	default: // generic JSON
		payload = inc
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(wh.URL, "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		s.logger.Warn("webhook: dispatch failed",
			zap.String("webhook_id", wh.ID),
			zap.String("url", wh.URL),
			zap.Error(err),
		)
		return
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode >= 400 {
		s.logger.Warn("webhook: non-2xx response",
			zap.String("webhook_id", wh.ID),
			zap.Int("status", resp.StatusCode),
		)
	}
}

func webhookSeverity(tier int) string {
	switch tier {
	case 4:
		return "critical"
	case 3:
		return "error"
	case 2:
		return "warning"
	default:
		return "info"
	}
}

// handleWebhooks dispatches webhook CRUD.
//
//	GET    /api/v1/config/webhooks     – list webhooks
//	POST   /api/v1/config/webhooks     – create webhook
//	PUT    /api/v1/config/webhooks/{id} – update webhook
//	DELETE /api/v1/config/webhooks/{id} – delete webhook
func (s *Server) handleWebhooks(w http.ResponseWriter, r *http.Request) {
	suffix := strings.TrimPrefix(r.URL.Path, "/api/v1/config/webhooks")
	suffix = strings.TrimPrefix(suffix, "/")

	switch {
	case r.Method == http.MethodGet && suffix == "":
		s.listWebhooks(w, r)
	case r.Method == http.MethodPost && suffix == "":
		s.createWebhook(w, r)
	case r.Method == http.MethodPut && suffix != "":
		s.updateWebhook(w, r, suffix)
	case r.Method == http.MethodDelete && suffix != "":
		s.deleteWebhook(w, r, suffix)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) listWebhooks(w http.ResponseWriter, _ *http.Request) {
	s.whStore.mu.RLock()
	defer s.whStore.mu.RUnlock()
	out := make([]*webhookConfig, 0, len(s.whStore.webhooks))
	for _, wh := range s.whStore.webhooks {
		out = append(out, wh)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"webhooks": out})
}

func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string        `json:"name"`
		URL     string        `json:"url"`
		MinTier int           `json:"min_tier"`
		Format  webhookFormat `json:"format"`
		Enabled bool          `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and url required"})
		return
	}
	if req.Format == "" {
		req.Format = WebhookFormatGeneric
	}
	wh := &webhookConfig{
		ID:        uuid.New().String(),
		Name:      req.Name,
		URL:       req.URL,
		MinTier:   req.MinTier,
		Format:    req.Format,
		Enabled:   req.Enabled,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	s.whStore.mu.Lock()
	s.whStore.webhooks[wh.ID] = wh
	s.whStore.mu.Unlock()
	writeJSON(w, http.StatusCreated, wh)
}

func (s *Server) updateWebhook(w http.ResponseWriter, r *http.Request, id string) {
	s.whStore.mu.Lock()
	defer s.whStore.mu.Unlock()
	wh, exists := s.whStore.webhooks[id]
	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook not found"})
		return
	}
	var req struct {
		Name    string        `json:"name"`
		URL     string        `json:"url"`
		MinTier *int          `json:"min_tier"`
		Format  webhookFormat `json:"format"`
		Enabled *bool         `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if req.Name != "" {
		wh.Name = req.Name
	}
	if req.URL != "" {
		wh.URL = req.URL
	}
	if req.MinTier != nil {
		wh.MinTier = *req.MinTier
	}
	if req.Format != "" {
		wh.Format = req.Format
	}
	if req.Enabled != nil {
		wh.Enabled = *req.Enabled
	}
	writeJSON(w, http.StatusOK, wh)
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request, id string) {
	s.whStore.mu.Lock()
	defer s.whStore.mu.Unlock()
	if _, exists := s.whStore.webhooks[id]; !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "webhook not found"})
		return
	}
	delete(s.whStore.webhooks, id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "id": id})
}
