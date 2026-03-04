// Package consoleapi implements the OpenGuard v5 console REST API server.
// It provides endpoints for event browsing, incident management, audit log
// access, and human approval workflows.
package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	auditled "github.com/DiniMuhd7/openguard/services/audit-ledger"
)

// contextKey is a typed key for values stored in request contexts.
type contextKey string

const contextKeyActor contextKey = "actor"

// Config holds configuration for the API Server.
type Config struct {
	// ListenAddr is the address to listen on (e.g. ":8080").
	ListenAddr string
	// JWTSecret is the HMAC secret for JWT token validation.
	JWTSecret string
	// ReadTimeout is the HTTP server read timeout.
	ReadTimeout time.Duration
	// WriteTimeout is the HTTP server write timeout.
	WriteTimeout time.Duration
}

// Server is the console API HTTP server.
type Server struct {
	cfg       Config
	ledger    *auditled.Ledger
	events    *EventStore
	incidents *IncidentStore
	logger    *zap.Logger
	srv       *http.Server
	registry  *prometheus.Registry

	// metrics
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec

	// credentials: username → bcrypt hash
	credentials map[string][]byte

	// activeProvider holds the currently selected AI model provider.
	activeProvider atomic.Value
}

// NewServer constructs a new console API Server.
func NewServer(cfg Config, ledger *auditled.Ledger, events *EventStore, incidents *IncidentStore, logger *zap.Logger) *Server {
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	reg := prometheus.NewRegistry()
	reqTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "openguard_http_requests_total",
		Help: "Total number of HTTP requests by method, path and status.",
	}, []string{"method", "path", "status"})
	reqDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "openguard_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})
	reg.MustRegister(reqTotal, reqDuration)

	// Load admin credentials from environment, defaulting to admin/changeme.
	adminUser := os.Getenv("OPENGUARD_ADMIN_USER")
	if adminUser == "" {
		adminUser = "admin"
	}
	adminHash := os.Getenv("OPENGUARD_ADMIN_BCRYPT_HASH")
	var hashBytes []byte
	if adminHash != "" {
		hashBytes = []byte(adminHash)
	} else {
		// Default: bcrypt of "changeme"
		h, _ := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
		hashBytes = h
	}
	creds := map[string][]byte{adminUser: hashBytes}

	// Determine the initial active provider from env, defaulting to openai-codex.
	// Set OPENGUARD_PROVIDER to override the default at startup (e.g. "anthropic-claude").
	provider := os.Getenv("OPENGUARD_PROVIDER")
	if provider == "" {
		provider = "openai-codex"
	}

	s := &Server{
		cfg:             cfg,
		ledger:          ledger,
		events:          events,
		incidents:       incidents,
		logger:          logger,
		registry:        reg,
		requestsTotal:   reqTotal,
		requestDuration: reqDuration,
		credentials:     creds,
	}
	s.activeProvider.Store(provider)
	return s
}

// responseWriter wraps http.ResponseWriter to capture the HTTP status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Start registers routes and begins listening for requests.
func (s *Server) Start(_ context.Context) error {
	mux := http.NewServeMux()

	// Login endpoint is registered directly on the mux — it is exempt from JWT auth.
	mux.HandleFunc("/api/v1/login", s.handleLogin)

	s.registerRoutes(mux)

	s.srv = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      s.corsMiddleware(s.loggingMiddleware(s.authMiddleware(mux))),
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: s.cfg.WriteTimeout,
	}

	go func() {
		s.logger.Info("console api: listening", zap.String("addr", s.cfg.ListenAddr))
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("console api: server error", zap.Error(err))
		}
	}()
	return nil
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	if s.srv != nil {
		return s.srv.Shutdown(ctx)
	}
	return nil
}

// registerRoutes wires all API routes to the provided mux.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/api/v1/events", s.handleEvents)
	mux.HandleFunc("/api/v1/events/", s.handleEvents)
	mux.HandleFunc("/api/v1/incidents", s.handleIncidents)
	mux.HandleFunc("/api/v1/audit", s.handleAudit)
	mux.HandleFunc("/api/v1/sensors", s.handleSensors)
	mux.HandleFunc("/api/v1/models", s.handleModels)
	mux.HandleFunc("/api/v1/models/active", s.handleModelsActive)

	// Incident detail and action endpoints — matched by prefix.
	mux.HandleFunc("/api/v1/incidents/", s.handleIncidentActions)

	// Serve the embedded React console for all other paths.
	// A custom handler falls back to index.html so React-Router
	// client-side navigation works correctly.
	uiHandler := uiFileSystem()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Try to serve the exact static asset first.
		path := r.URL.Path
		if path == "/" || path == "" {
			path = "/index.html"
		}
		// For asset files (js/css/svg/png), serve directly.
		f, err := uiFiles.Open("ui" + path)
		if err == nil {
			f.Close()
			uiHandler.ServeHTTP(w, r)
			return
		}
		// Fallback: serve index.html for client-side routes.
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		uiHandler.ServeHTTP(w, r2)
	})
}

// handleLogin handles POST /api/v1/login.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username and password required"})
		return
	}
	hash, ok := s.credentials[req.Username]
	if !ok || bcrypt.CompareHashAndPassword(hash, []byte(req.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	claims := jwtv5.MapClaims{
		"sub": req.Username,
		"exp": jwtv5.NewNumericDate(time.Now().Add(8 * time.Hour)),
	}
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(s.cfg.JWTSecret))
	if err != nil {
		s.logger.Error("console api: jwt sign failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": signed})
}

// handleHealth responds to GET /health with a 200 OK.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": "5.0.0"})
}

// handleMetrics responds to GET /metrics using the Prometheus registry.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

// handleEvents handles GET /api/v1/events and GET /api/v1/events/:id.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Detect /api/v1/events/:id — path must have something after the trailing slash.
	if r.URL.Path != "/api/v1/events" && r.URL.Path != "/api/v1/events/" {
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/events/")
		if id != "" {
			event, ok := s.events.Get(id)
			if !ok {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
				return
			}
			writeJSON(w, http.StatusOK, event)
			return
		}
	}
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	items, total := s.events.List(page, 50)
	if items == nil {
		items = []map[string]interface{}{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events": items,
		"page":   page,
		"total":  total,
	})
}

// handleIncidents handles GET /api/v1/incidents.
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	items, total := s.incidents.List(page, 50)
	if items == nil {
		items = []*Incident{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"incidents": items,
		"page":      page,
		"total":     total,
	})
}

// handleIncidentActions handles GET /api/v1/incidents/:id and
// POST /api/v1/incidents/:id/{approve,deny,override}.
func (s *Server) handleIncidentActions(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/")
	parts := strings.SplitN(path, "/", 2)

	// GET /api/v1/incidents/:id — single incident lookup.
	if r.Method == http.MethodGet {
		if len(parts) != 1 || parts[0] == "" {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		incident, ok := s.incidents.Get(parts[0])
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "incident not found"})
			return
		}
		writeJSON(w, http.StatusOK, incident)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(parts) != 2 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	incidentID, action := parts[0], parts[1]

	// Validate action.
	switch action {
	case "approve", "deny", "override":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid action"})
		return
	}

	// Map action to status (override → overridden, approve → approved, deny → denied).
	var status string
	switch action {
	case "approve":
		status = "approved"
	case "deny":
		status = "denied"
	case "override":
		status = "overridden"
	default:
		status = action + "d"
	}

	// Persist the status change.
	s.incidents.UpdateStatus(incidentID, status)

	// Write audit ledger entry.
	actor, _ := r.Context().Value(contextKeyActor).(string)
	if actor == "" {
		actor = "operator"
	}
	entry := auditled.AuditEntry{
		EventID:  incidentID,
		Actor:    actor,
		Action:   action,
		Decision: status,
	}
	if err := s.ledger.Append(r.Context(), entry); err != nil {
		s.logger.Warn("console api: audit append failed", zap.Error(err))
	}

	s.logger.Info("console api: incident action",
		zap.String("incident_id", incidentID),
		zap.String("action", action),
		zap.String("remote_addr", r.RemoteAddr),
	)
	writeJSON(w, http.StatusAccepted, map[string]string{
		"incident_id": incidentID,
		"action":      action,
		"status":      "accepted",
	})
}

// handleAudit handles GET /api/v1/audit with optional event_id query parameter.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	eventID := r.URL.Query().Get("event_id")
	entries, err := s.ledger.GetByEventID(r.Context(), eventID)
	if err != nil {
		s.logger.Error("console api: audit query failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"entries": entries})
}

// handleSensors handles GET /api/v1/sensors, returning metadata for all
// OpenGuard sensor adapters (HostGuard, AgentGuard, CommsGuard).
func (s *Server) handleSensors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	type sensorInfo struct {
		ID          string                 `json:"id"`
		Name        string                 `json:"name"`
		Description string                 `json:"description"`
		ListenAddr  string                 `json:"listen_addr"`
		Subsystems  []string               `json:"subsystems"`
		Config      map[string]interface{} `json:"config"`
	}

	sensors := []sensorInfo{
		{
			ID:          "hostguard",
			Name:        "HostGuard",
			Description: "Cross-platform host sensor that monitors OS-level activity for threats and anomalies.",
			ListenAddr:  "N/A (publishes via NATS)",
			Subsystems: []string{
				"process",
				"realtime_process",
				"file_io",
				"hidden_process",
				"systemd",
				"cron",
				"network",
				"resource",
				"kernel_module",
				"session",
				"dns",
				"ipc",
				"container",
				"usb",
				"ebpf_syscall",
				"cloud_metadata",
				"firmware",
			},
			Config: map[string]interface{}{
				"nats_topic":              "openguard.hostguard.raw",
				"poll_interval":           "5s",
				"hidden_scan_interval":    "60s",
				"cpu_percent_high":        90.0,
				"memory_mb_high":          2048.0,
				"new_process_burst":       20,
				"sensitive_path_prefixes": []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root", "/root/.ssh", "/boot"},
				"allowed_dns_resolvers":   []string{"8.8.8.8", "1.1.1.1", "8.8.4.4", "9.9.9.9", "208.67.222.222"},
			},
		},
		{
			ID:          "agentguard",
			Name:        "AgentGuard",
			Description: "AI agent action interception sensor that enforces policy compliance and manages agent lifecycles.",
			ListenAddr:  ":8095",
			Subsystems: []string{
				"action_interception",
				"agent_registry",
				"policy_compliance",
				"suspension",
				"quarantine",
			},
			Config: map[string]interface{}{
				"nats_topic":  "openguard.agentguard.raw",
				"listen_addr": ":8095",
				"routes": []string{
					"POST /agent/action",
					"POST /agent/register",
					"GET  /agent/list",
					"GET  /agent/status/{agent_id}",
					"POST /agent/unsuspend/{agent_id}",
				},
			},
		},
		{
			ID:          "commsguard",
			Name:        "CommsGuard",
			Description: "Multi-channel communications sensor that aggregates webhooks from messaging platforms and detects threats.",
			ListenAddr:  ":8090",
			Subsystems: []string{
				"whatsapp",
				"telegram",
				"messenger",
				"twilio_sms",
				"twilio_voice",
				"twitter",
			},
			Config: map[string]interface{}{
				"nats_topic":              "openguard.commsguard.raw",
				"listen_addr":             ":8090",
				"bulk_message_threshold":  20,
				"bulk_message_window":     "60s",
				"enable_content_analysis": true,
				"webhook_routes": []string{
					"/whatsapp/webhook",
					"/telegram/webhook",
					"/messenger/webhook",
					"/twilio/sms",
					"/twilio/voice",
					"/twitter/webhook",
				},
			},
		},
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"sensors": sensors})
}

// modelProvider describes an available AI model provider.
type modelProvider struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Available bool   `json:"available"`
}

// knownProviders lists all supported AI model providers and their env key vars.
var knownProviders = []struct {
	id     string
	name   string
	envKey string
}{
	{"openai-codex", "OpenAI (GPT-4o)", "OPENAI_API_KEY"},
	{"anthropic-claude", "Anthropic (Claude)", "ANTHROPIC_API_KEY"},
	{"google-gemini", "Google (Gemini 1.5 Pro)", "GEMINI_API_KEY"},
}

// handleModels handles GET /api/v1/models.
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	active, _ := s.activeProvider.Load().(string)
	providers := make([]modelProvider, 0, len(knownProviders))
	for _, p := range knownProviders {
		providers = append(providers, modelProvider{
			ID:        p.id,
			Name:      p.name,
			Available: os.Getenv(p.envKey) != "",
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active":    active,
		"providers": providers,
	})
}

// isValidProvider reports whether id matches one of the known provider IDs.
func isValidProvider(id string) bool {
	for _, p := range knownProviders {
		if p.id == id {
			return true
		}
	}
	return false
}

// handleModelsActive handles POST /api/v1/models/active.
func (s *Server) handleModelsActive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Provider string `json:"provider"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Provider == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider is required"})
		return
	}
	if !isValidProvider(req.Provider) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown provider"})
		return
	}
	s.activeProvider.Store(req.Provider)
	writeJSON(w, http.StatusOK, map[string]string{"active": req.Provider})
}

// corsMiddleware adds CORS headers to every response and handles OPTIONS preflight.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authMiddleware validates JWT Bearer tokens on all non-health/metrics/login endpoints.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health, metrics, and login endpoints are unauthenticated.
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" || r.URL.Path == "/api/v1/login" {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(auth, "Bearer ")
		token, err := jwtv5.Parse(tokenStr, func(t *jwtv5.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwtv5.SigningMethodHMAC); !ok {
				return nil, jwtv5.ErrSignatureInvalid
			}
			return []byte(s.cfg.JWTSecret), nil
		}, jwtv5.WithValidMethods([]string{"HS256"}))
		if err != nil || !token.Valid {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		claims, ok := token.Claims.(jwtv5.MapClaims)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		subject, _ := claims.GetSubject()
		ctx := context.WithValue(r.Context(), contextKeyActor, subject)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loggingMiddleware logs each request, records Prometheus metrics, and captures HTTP status.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)
		statusStr := strconv.Itoa(rw.status)
		s.requestsTotal.WithLabelValues(r.Method, r.URL.Path, statusStr).Inc()
		s.requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration.Seconds())
		s.logger.Info("console api: request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", rw.status),
			zap.Duration("latency", duration),
			zap.String("remote_addr", r.RemoteAddr),
		)
	})
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// If encoding fails, response headers are already sent; log the error.
		http.Error(w, "encode error", http.StatusInternalServerError)
	}
}
