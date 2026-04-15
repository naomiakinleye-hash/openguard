// Package consoleapi implements the OpenGuard v5 console REST API server.
// It provides endpoints for event browsing, incident management, audit log
// access, and human approval workflows.
package consoleapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	nats "github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	auditled "github.com/DiniMuhd7/openguard/services/audit-ledger"
	"github.com/DiniMuhd7/openguard/services/baseline"
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
	// NATSUrl is the NATS server URL used to publish live model-provider config
	// updates to the model-gateway agent whenever the active provider or its
	// API key changes in Model Settings. Leave empty to disable publishing.
	NATSUrl string
	// ModelConfigTopic is the NATS subject the model-gateway subscribes to for
	// live config updates. Defaults to "openguard.modelguard.config".
	ModelConfigTopic string
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

	// db is the optional SQLite database for user persistence. Nil when SQLite is disabled.
	db *sql.DB

	// usersMu protects the users map.
	usersMu sync.RWMutex
	// users: username → userRecord (role, bcrypt hash, metadata).
	users map[string]*userRecord
	// whStore holds outbound webhook configurations.
	whStore *webhookStore
	// scStore holds detected supply-chain events.
	scStore *scStore
	// baselineEngine performs behavioural anomaly scoring; may be nil.
	baselineEngine *baseline.Engine

	// activeProvider holds the currently selected AI model provider.
	activeProvider atomic.Value

	// userCreds stores per-user, per-provider OAuth2 tokens and API key credentials.
	// Key format: "username\x00provider" (see credKey in oauth.go). Value: *providerCredential.
	userCreds sync.Map

	// oauthStates holds in-flight OAuth2 state tokens for CSRF protection.
	// Key: state string. Value: *oauthState. States expire after 10 minutes.
	oauthStates sync.Map

	// commsConfig holds runtime configuration for all CommsGuard channels.
	commsConfig *commsConfig

	// agentGuardStore holds the in-memory agent registry for the AgentGuard console.
	agentGuardStore *agentStore

	// modelGuard holds ModelGuard runtime state (audit entries, guardrail config).
	modelGuard *modelGuardState

	// configStore holds all runtime-mutable configuration for all domains.
	configStore *domainConfigStore

	// waSession manages the WhatsApp multi-device (QR-code) live session.
	waSession *waSession

	// tgSession manages the Telegram Bot API long-polling session.
	tgSession *tgSession

	// natsConn is the NATS connection used to publish live model-provider config
	// updates to the model-gateway agent. Nil when NATSUrl is not configured.
	natsConn         *nats.Conn
	modelConfigTopic string
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
	var adminHashBytes []byte
	if adminHash != "" {
		adminHashBytes = []byte(adminHash)
	} else {
		// Default: bcrypt of "changeme"
		h, _ := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
		adminHashBytes = h
	}
	users := map[string]*userRecord{
		adminUser: {
			Username:     adminUser,
			PasswordHash: adminHashBytes,
			Role:         RoleAdmin,
			CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		},
	}

	// Determine the initial active provider from env, defaulting to openai-codex.
	// Set OPENGUARD_PROVIDER to override the default at startup (e.g. "anthropic-claude").
	provider := os.Getenv("OPENGUARD_PROVIDER")
	if provider == "" {
		provider = "openai-codex"
	}

	s := &Server{
		cfg:              cfg,
		ledger:           ledger,
		events:           events,
		incidents:        incidents,
		logger:           logger,
		registry:         reg,
		requestsTotal:    reqTotal,
		requestDuration:  reqDuration,
		users:            users,
		whStore:          newWebhookStore(),
		scStore:          newSCStore(),
		commsConfig:      newCommsConfig(),
		agentGuardStore:  newAgentStore(),
		modelGuard:       newModelGuardState(),
		configStore:      newDomainConfigStore(),
		waSession:        newWASession(cfg.NATSUrl, logger),
		tgSession:        newTGSession(logger),
		modelConfigTopic: cfg.ModelConfigTopic,
	}
	if s.modelConfigTopic == "" {
		s.modelConfigTopic = "openguard.modelguard.config"
	}
	s.activeProvider.Store(provider)

	// Pre-populate the ModelGuard call store from the persisted audit log so
	// that stats and audit views reflect real AI enrichment history immediately
	// on startup, without waiting for new live calls.
	s.modelGuard.calls.loadAuditFile("audit/model-gateway-audit.ndjson")

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
func (s *Server) Start(ctx context.Context) error {
	if s.waSession != nil {
		go s.waSession.Start(ctx)
	}
	if s.tgSession != nil {
		go s.tgSession.Start(ctx)
	}

	// Connect to NATS for model-config publishing (best-effort — non-fatal).
	if s.cfg.NATSUrl != "" {
		nc, err := nats.Connect(s.cfg.NATSUrl,
			nats.Name("openguard-console-api"),
			nats.MaxReconnects(-1),
		)
		if err != nil {
			s.logger.Warn("console api: NATS connect failed — model-config publishing disabled",
				zap.String("nats_url", s.cfg.NATSUrl), zap.Error(err))
		} else {
			s.natsConn = nc
			s.logger.Info("console api: NATS connected for model-config publishing",
				zap.String("topic", s.modelConfigTopic))
		}
	}
	mux := http.NewServeMux()

	// Login endpoint is registered directly on the mux — it is exempt from JWT auth.
	mux.HandleFunc("/api/v1/login", s.handleLogin)
	mux.HandleFunc("/api/v1/account", s.handleAccount)

	s.registerRoutes(mux)

	s.srv = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      s.corsMiddleware(s.loggingMiddleware(s.authMiddleware(mux))),
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: s.cfg.WriteTimeout,
	}

	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("console api: listen on %s: %w", s.cfg.ListenAddr, err)
	}

	go func() {
		s.logger.Info("console api: listening", zap.String("addr", s.cfg.ListenAddr))
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("console api: server error", zap.Error(err))
		}
	}()

	// Watch the EventStore for real domain="agent" events so the AgentGuard
	// store stays in sync without requiring demo data.
	go s.watchAgentEvents(ctx)

	return nil
}

// Stop gracefully shuts down the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	if s.waSession != nil {
		s.waSession.Stop()
	}
	if s.tgSession != nil {
		s.tgSession.Stop()
	}
	if s.natsConn != nil {
		s.natsConn.Drain() //nolint:errcheck
		s.natsConn = nil
	}
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
	// SSE stream must be registered before the wildcard /api/v1/events/ route.
	mux.HandleFunc("/api/v1/events/stream", s.handleEventsStream)
	mux.HandleFunc("/api/v1/events/", s.handleEvents)
	mux.HandleFunc("/api/v1/incidents", s.handleIncidents)
	mux.HandleFunc("/api/v1/audit", s.handleAudit)
	mux.HandleFunc("/api/v1/sensors", s.handleSensors)
	mux.HandleFunc("/api/v1/models", s.handleModels)
	mux.HandleFunc("/api/v1/models/active", s.handleModelsActive)
	mux.HandleFunc("/api/v1/models/oauth/start", s.handleOAuthStart)
	mux.HandleFunc("/api/v1/models/oauth/callback", s.handleOAuthCallback)
	mux.HandleFunc("/api/v1/models/credentials", s.handleCredentials)
	mux.HandleFunc("/api/v1/system/stats", s.handleSystemStats)
	mux.HandleFunc("/api/v1/stats/kpi", s.handleKPIStats)
	mux.HandleFunc("/api/v1/summary", s.handleSummary)

	// CommsGuard-specific endpoints.
	mux.HandleFunc("/api/v1/commsguard/whatsapp/status", s.handleWAStatus)
	mux.HandleFunc("/api/v1/commsguard/whatsapp/qr", s.handleWAQR)
	mux.HandleFunc("/api/v1/commsguard/whatsapp/messages", s.handleWAMessages)
	mux.HandleFunc("/api/v1/commsguard/whatsapp/connect", s.handleWAConnect)
	mux.HandleFunc("/api/v1/commsguard/whatsapp/logout", s.handleWALogout)
	mux.HandleFunc("/api/v1/commsguard/telegram/status", s.handleTGStatus)
	mux.HandleFunc("/api/v1/commsguard/telegram/messages", s.handleTGMessages)
	mux.HandleFunc("/api/v1/commsguard/telegram/connect", s.handleTGConnect)
	mux.HandleFunc("/api/v1/commsguard/telegram/disconnect", s.handleTGDisconnect)
	mux.HandleFunc("/api/v1/commsguard/stats", s.handleCommsGuardStats)
	mux.HandleFunc("/api/v1/commsguard/events", s.handleCommsGuardEvents)
	mux.HandleFunc("/api/v1/commsguard/channels", s.handleCommsGuardChannels)
	mux.HandleFunc("/api/v1/commsguard/config", s.handleCommsGuardConfig)
	// AgentGuard-specific endpoints.
	mux.HandleFunc("/api/v1/agentguard/stats", s.handleAgentGuardStats)
	mux.HandleFunc("/api/v1/agentguard/agents", s.handleAgentGuardAgents)
	mux.HandleFunc("/api/v1/agentguard/agents/", s.handleAgentGuardAgentsPrefix)
	mux.HandleFunc("/api/v1/agentguard/events", s.handleAgentGuardEvents)
	mux.HandleFunc("/api/v1/agentguard/rules", s.handleAgentGuardRules)

	// HostGuard-specific endpoints.
	mux.HandleFunc("/api/v1/hostguard/stats", s.handleHostGuardStats)
	mux.HandleFunc("/api/v1/hostguard/events", s.handleHostGuardEvents)
	mux.HandleFunc("/api/v1/hostguard/rules", s.handleHostGuardRules)

	// NetworkGuard-specific endpoints.
	mux.HandleFunc("/api/v1/networkguard/stats", s.handleNetworkGuardStats)
	mux.HandleFunc("/api/v1/networkguard/events", s.handleNetworkGuardEvents)
	mux.HandleFunc("/api/v1/networkguard/rules", s.handleNetworkGuardRules)

	// ModelGuard-specific endpoints (all dispatched through a single prefix handler).
	mux.HandleFunc("/api/v1/modelguard/", s.handleModelGuardPrefix)
	mux.HandleFunc("/api/v1/modelguard/stats", s.handleModelGuardStats)
	mux.HandleFunc("/api/v1/modelguard/audit", s.handleModelGuardAudit)
	mux.HandleFunc("/api/v1/modelguard/providers", s.handleModelGuardProviders)
	mux.HandleFunc("/api/v1/modelguard/guardrails", s.handleModelGuardGuardrails)
	mux.HandleFunc("/api/v1/modelguard/requests", s.handleModelGuardRequests)

	// Unified per-domain configuration CRUD endpoints.
	mux.HandleFunc("/api/v1/config/", s.handleConfigPrefix)

	// Webhook configuration (operator+ role required). Must be registered before
	// the generic /api/v1/config/ subtree so the more-specific path wins.
	mux.HandleFunc("/api/v1/config/webhooks", s.requireRole(RoleOperator, s.handleWebhooks))
	mux.HandleFunc("/api/v1/config/webhooks/", s.requireRole(RoleOperator, s.handleWebhooks))

	// User management (admin role required).
	mux.HandleFunc("/api/v1/users", s.requireRole(RoleAdmin, s.handleUsers))
	mux.HandleFunc("/api/v1/users/", s.requireRole(RoleAdmin, s.handleUsers))

	// Supply-chain guard telemetry.
	mux.HandleFunc("/api/v1/supplychain", s.handleSupplyChain)
	mux.HandleFunc("/api/v1/supplychain/stats", s.handleSupplyChainStats)

	// Behavioural baseline statistics.
	mux.HandleFunc("/api/v1/baseline", s.handleBaseline)

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
	s.usersMu.RLock()
	u, ok := s.users[req.Username]
	s.usersMu.RUnlock()
	if !ok || bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(req.Password)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	claims := jwtv5.MapClaims{
		"sub":  req.Username,
		"role": string(u.Role),
		"exp":  jwtv5.NewNumericDate(time.Now().Add(8 * time.Hour)),
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

// handleAccount handles PUT /api/v1/account — authenticated endpoint that lets
// the current user change their username and/or password.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The actor comes from the JWT claim set by authMiddleware.
	currentUser, _ := r.Context().Value(contextKeyActor).(string)
	if currentUser == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewUsername     string `json:"new_username"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.CurrentPassword == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "current_password is required"})
		return
	}
	if req.NewUsername == "" && req.NewPassword == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new_username or new_password is required"})
		return
	}

	s.usersMu.Lock()
	defer s.usersMu.Unlock()

	record, ok := s.users[currentUser]
	if !ok || bcrypt.CompareHashAndPassword(record.PasswordHash, []byte(req.CurrentPassword)) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
		return
	}

	newUser := req.NewUsername
	if newUser == "" {
		newUser = currentUser
	}
	// Reject if the new username is already taken by a different account.
	if newUser != currentUser {
		if _, exists := s.users[newUser]; exists {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "username already taken"})
			return
		}
	}

	// Update password if requested.
	if req.NewPassword != "" {
		newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			s.logger.Error("console api: bcrypt failed", zap.Error(err))
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		record.PasswordHash = newHash
	}

	// Rename if requested: move record to new key.
	if newUser != currentUser {
		delete(s.users, currentUser)
		record.Username = newUser
		s.users[newUser] = record
		go sqliteDeleteUser(s.db, currentUser)
	}
	go sqliteUpsertUser(s.db, record)

	s.logger.Info("console api: account updated",
		zap.String("actor", currentUser),
		zap.String("new_username", newUser),
		zap.Bool("password_changed", req.NewPassword != ""),
	)
	writeJSON(w, http.StatusOK, map[string]string{"username": newUser})
}

// handleHealth responds to GET /health with real subsystem status.
// status is "ok" when all configured subsystems are healthy, "degraded" when
// a non-fatal subsystem (NATS) is unavailable.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := "ok"
	subsystems := map[string]string{}

	// NATS connectivity — degraded but not fatal when down.
	if s.natsConn != nil {
		if s.natsConn.IsConnected() {
			subsystems["nats"] = "connected"
		} else {
			subsystems["nats"] = s.natsConn.Status().String()
			status = "degraded"
		}
	} else {
		subsystems["nats"] = "not_configured"
	}

	// EventStore — report live event count.
	_, evTotal := s.events.List(1, 1)
	subsystems["event_store"] = fmt.Sprintf("%d events", evTotal)

	// IncidentStore — report live incident count.
	_, incTotal := s.incidents.List(1, 1)
	subsystems["incident_store"] = fmt.Sprintf("%d incidents", incTotal)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     status,
		"version":    "5.0.0",
		"subsystems": subsystems,
	})
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

// handleEventsStream handles GET /api/v1/events/stream using Server-Sent Events (SSE).
// The client receives one JSON-encoded event per SSE message as events are ingested.
// Because EventSource cannot attach custom headers, authentication is accepted via
// the ?token= query param in addition to the standard Bearer header.
func (s *Server) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify the ResponseWriter supports flushing (required for SSE).
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	// Set SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Needed when the frontend dev server and API run on different origins.
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Subscribe to new events. The channel is closed on unsubscribe.
	ch := s.events.Subscribe()
	defer s.events.Unsubscribe(ch)

	enc := json.NewEncoder(w)

	for {
		select {
		case event, open := <-ch:
			if !open {
				return
			}
			if _, err := fmt.Fprint(w, "data: "); err != nil {
				return
			}
			if err := enc.Encode(event); err != nil {
				return
			}
			if _, err := fmt.Fprint(w, "\n"); err != nil {
				return
			}
			flusher.Flush()

		case <-r.Context().Done():
			return
		}
	}
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
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	const pageSize = 100
	entries, err := s.ledger.GetByEventID(r.Context(), eventID)
	if err != nil {
		s.logger.Error("console api: audit query failed", zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	total := len(entries)
	// Apply pagination.
	start := (page - 1) * pageSize
	end := start + pageSize
	if start >= total {
		entries = nil
	} else {
		if end > total {
			end = total
		}
		entries = entries[start:end]
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"page":    page,
		"total":   total,
	})
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
	Available bool   `json:"available"`  // true when the user has connected this provider
	UsesOAuth bool   `json:"uses_oauth"` // true when sign-in uses OAuth2 (false = API key form)
}

// knownProviders lists all supported AI model providers.
var knownProviders = []struct {
	id   string
	name string
}{
	{"openai-codex", "OpenAI (GPT-4o)"},
	{"anthropic-claude", "Anthropic (Claude)"},
	{"google-gemini", "Google (Gemini 1.5 Pro)"},
}

// modelConfigUpdate is the JSON payload published to the model-gateway config topic.
// The model-gateway agent subscribes to this topic and hot-swaps its active provider
// without requiring a restart.
type modelConfigUpdate struct {
	Provider string `json:"provider"` // canonical gateway name: "codex", "claude", "gemini"
	APIKey   string `json:"api_key"`  // empty string means the provider was disconnected
}

// uiProviderToGateway maps console-UI provider IDs to the names the model-gateway recognises.
var uiProviderToGateway = map[string]string{
	"openai-codex":     "codex",
	"anthropic-claude": "claude",
	"google-gemini":    "gemini",
}

// publishModelConfig resolves the API key for the given user+provider pair and
// publishes a modelConfigUpdate to the model-gateway config topic.
// If the NATS connection is nil or the user has no credential, a warning is logged
// and the call is a no-op — this never returns an error so callers can fire-and-forget.
func (s *Server) publishModelConfig(username, uiProvider string) {
	if s.natsConn == nil {
		return
	}
	gatewayName, ok := uiProviderToGateway[uiProvider]
	if !ok {
		return // unknown provider — silently ignore
	}
	apiKey := ""
	if cred, found := s.getUserCred(username, uiProvider); found {
		apiKey = cred.AccessToken
	}
	update := modelConfigUpdate{Provider: gatewayName, APIKey: apiKey}
	data, err := json.Marshal(update)
	if err != nil {
		s.logger.Warn("console api: failed to marshal model config update", zap.Error(err))
		return
	}
	if err := s.natsConn.Publish(s.modelConfigTopic, data); err != nil {
		s.logger.Warn("console api: failed to publish model config update",
			zap.String("topic", s.modelConfigTopic), zap.Error(err))
		return
	}
	s.logger.Info("console api: model config published to model-gateway",
		zap.String("provider", gatewayName),
		zap.String("topic", s.modelConfigTopic),
		zap.Bool("has_key", apiKey != ""),
	)
}

// handleModels handles GET /api/v1/models.
func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username, _ := r.Context().Value(contextKeyActor).(string)
	active, _ := s.activeProvider.Load().(string)
	providers := make([]modelProvider, 0, len(knownProviders))
	for _, p := range knownProviders {
		providers = append(providers, modelProvider{
			ID:        p.id,
			Name:      p.name,
			Available: s.isUserConnected(username, p.id),
			UsesOAuth: hasOAuth(p.id),
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
	username, _ := r.Context().Value(contextKeyActor).(string)
	// Publish the new provider (with the calling user's stored API key) to the
	// model-gateway so it can hot-swap its active provider without restarting.
	s.publishModelConfig(username, req.Provider)
	writeJSON(w, http.StatusOK, map[string]string{"active": req.Provider})
}

// corsMiddleware adds CORS headers to every response and handles OPTIONS preflight.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authMiddleware validates JWT Bearer tokens on all /api/v1/* endpoints except login.
// Static UI assets (/, /assets/*, /index.html, etc.) are served without authentication
// so the React app can load and display the login page.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health, metrics, login and all non-API paths are unauthenticated.
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" ||
			r.URL.Path == "/api/v1/login" ||
			r.URL.Path == "/api/v1/models/oauth/callback" || // browser redirect from OAuth2 provider
			!strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		var tokenStr string
		if strings.HasPrefix(auth, "Bearer ") {
			tokenStr = strings.TrimPrefix(auth, "Bearer ")
		} else {
			// EventSource cannot set custom headers; accept token as a query param
			// for the SSE stream endpoint as a fallback.
			tokenStr = r.URL.Query().Get("token")
		}
		if tokenStr == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
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
		role, _ := claims["role"].(string)
		ctx := context.WithValue(r.Context(), contextKeyActor, subject)
		ctx = context.WithValue(ctx, contextKeyRole, UserRole(role))
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

// handleBaseline handles GET /api/v1/baseline — returns current behavioural
// baseline statistics from the EWMA engine.
func (s *Server) handleBaseline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.baselineEngine == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"entities": []interface{}{}})
		return
	}
	stats := s.baselineEngine.Stats()
	writeJSON(w, http.StatusOK, map[string]interface{}{"entities": stats})
}

// SetBaselineEngine wires the behavioural baseline engine into the console API
// server after construction (called from main.go).
func (s *Server) SetBaselineEngine(e *baseline.Engine) {
	s.baselineEngine = e
}

// SetDB enables SQLite user persistence. It loads previously persisted users
// from the database; if none exist (fresh DB) it seeds the database with the
// current in-memory users (the default admin account).
func (s *Server) SetDB(db *sql.DB) {
	s.db = db
	if db == nil {
		return
	}
	users, err := LoadUsersFromSQLite(db)
	if err != nil || len(users) == 0 {
		// Seed the DB with the current in-memory defaults.
		s.usersMu.RLock()
		for _, u := range s.users {
			sqliteUpsertUser(db, u)
		}
		s.usersMu.RUnlock()
		return
	}
	// Replace the in-memory map with what was persisted.
	s.usersMu.Lock()
	s.users = make(map[string]*userRecord, len(users))
	for _, u := range users {
		s.users[u.Username] = u
	}
	s.usersMu.Unlock()
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
