// Package consoleapi implements the OpenGuard v5 console REST API server.
// It provides endpoints for event browsing, incident management, audit log
// access, and human approval workflows.
package consoleapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	auditled "github.com/DiniMuhd7/openguard/services/audit-ledger"
)

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
	cfg      Config
	ledger   *auditled.Ledger
	logger   *zap.Logger
	srv      *http.Server
	registry *prometheus.Registry

	// metrics
	requestsTotal *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
}

// NewServer constructs a new console API Server.
func NewServer(cfg Config, ledger *auditled.Ledger, logger *zap.Logger) *Server {
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 30 * time.Second
	}
	reg := prometheus.NewRegistry()
	reqTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "openguard_http_requests_total",
		Help: "Total number of HTTP requests by method and path.",
	}, []string{"method", "path"})
	reqDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "openguard_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})
	reg.MustRegister(reqTotal, reqDuration)
	return &Server{
		cfg:             cfg,
		ledger:          ledger,
		logger:          logger,
		registry:        reg,
		requestsTotal:   reqTotal,
		requestDuration: reqDuration,
	}
}

// Start registers routes and begins listening for requests.
func (s *Server) Start(_ context.Context) error {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	s.srv = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      s.loggingMiddleware(s.authMiddleware(mux)),
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
	mux.HandleFunc("/api/v1/incidents", s.handleIncidents)
	mux.HandleFunc("/api/v1/audit", s.handleAudit)
	mux.HandleFunc("/api/v1/sensors", s.handleSensors)

	// Incident action endpoints — matched by prefix.
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
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events": []interface{}{},
		"page":   1,
		"total":  0,
	})
}

// handleIncidents handles GET /api/v1/incidents.
func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"incidents": []interface{}{},
		"page":      1,
		"total":     0,
	})
}

// handleIncidentActions handles POST .../approve, .../deny, .../override.
func (s *Server) handleIncidentActions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) != 2 {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	incidentID, action := parts[0], parts[1]
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

// authMiddleware validates JWT Bearer tokens on all non-health endpoints.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health and metrics endpoints are unauthenticated.
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Stub: full implementation validates JWT against s.cfg.JWTSecret.
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs each request and records Prometheus metrics.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)
		s.requestsTotal.WithLabelValues(r.Method, r.URL.Path).Inc()
		s.requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration.Seconds())
		s.logger.Info("console api: request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
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
