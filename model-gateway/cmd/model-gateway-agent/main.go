// main.go — ModelGuard Agent
// A deployable binary that subscribes to NATS model request messages,
// runs them through the prompt-sanitization and output-validation pipeline,
// dispatches to the configured AI model provider(s), and publishes results.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/DiniMuhd7/openguard/model-gateway/audit"
	"github.com/DiniMuhd7/openguard/model-gateway/guardrails"
	mg "github.com/DiniMuhd7/openguard/model-gateway/interfaces"
	"github.com/DiniMuhd7/openguard/model-gateway/providers/claude"
	"github.com/DiniMuhd7/openguard/model-gateway/providers/codex"
	"github.com/DiniMuhd7/openguard/model-gateway/providers/gemini"
	"github.com/DiniMuhd7/openguard/model-gateway/routing"
	"github.com/DiniMuhd7/openguard/model-gateway/toolcheck"
)

// modelRequest is the JSON schema for incoming NATS model requests.
type modelRequest struct {
	EventID    string   `json:"event_id"`
	AgentID    string   `json:"agent_id"`
	Prompt     string   `json:"prompt"`
	ToolCalls  []string `json:"tool_calls,omitempty"`
	RiskLevel  string   `json:"risk_level"`
	Domain     string   `json:"domain"`
	Indicators []string `json:"indicators"`
	Signature  string   `json:"signature,omitempty"`
}

// modelResponse is the JSON schema published to the result topic.
type modelResponse struct {
	EventID    string             `json:"event_id"`
	Result     *mg.AnalysisResult `json:"result,omitempty"`
	Error      string             `json:"error,omitempty"`
	Redactions []string           `json:"redactions,omitempty"`
}

// rateLimiter tracks per-agent call counts within a rolling minute window.
type rateLimiter struct {
	mu       sync.Mutex
	counts   map[string][]time.Time
	limitRPM int
}

func newRateLimiter(limitRPM int) *rateLimiter {
	return &rateLimiter{
		counts:   make(map[string][]time.Time),
		limitRPM: limitRPM,
	}
}

// allow returns true if the agent is within rate limit, false if exceeded.
func (rl *rateLimiter) allow(agentID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	times := rl.counts[agentID]
	// Remove entries older than one minute.
	j := 0
	for _, t := range times {
		if t.After(cutoff) {
			times[j] = t
			j++
		}
	}
	times = times[:j]
	if len(times) >= rl.limitRPM {
		rl.counts[agentID] = times
		return false
	}
	rl.counts[agentID] = append(times, now)
	return true
}

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic("model-gateway-agent: failed to init logger: " + err.Error())
	}
	defer logger.Sync() //nolint:errcheck

	// ── Read configuration from environment ─────────────────────────────────
	natsURL := envOr("OPENGUARD_NATS_URL", "nats://localhost:4222")
	modelTopic := envOr("OPENGUARD_MODEL_TOPIC", "openguard.modelguard.requests")
	resultTopic := envOr("OPENGUARD_RESULT_TOPIC", "openguard.modelguard.results")
	providerName := envOr("OPENGUARD_PROVIDER", "codex")
	strategy := envOr("OPENGUARD_RISK_STRATEGY", "single")

	openAIKey := os.Getenv("OPENGUARD_OPENAI_API_KEY")
	anthropicKey := os.Getenv("OPENGUARD_ANTHROPIC_API_KEY")
	geminiKey := os.Getenv("OPENGUARD_GEMINI_API_KEY")

	sigSecret := os.Getenv("OPENGUARD_MSG_HMAC_SECRET")

	rateLimitRPM := 60
	if v := os.Getenv("OPENGUARD_RATE_LIMIT_RPM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			rateLimitRPM = n
		}
	}

	minConfidence := 0.0
	if v := os.Getenv("OPENGUARD_MIN_CONFIDENCE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			minConfidence = f
		} else {
			logger.Warn("model-gateway-agent: invalid OPENGUARD_MIN_CONFIDENCE", zap.Error(err))
		}
	}

	maxPromptLength := 8192
	if v := os.Getenv("OPENGUARD_MAX_PROMPT_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxPromptLength = n
		} else {
			logger.Warn("model-gateway-agent: invalid OPENGUARD_MAX_PROMPT_LENGTH", zap.Error(err))
		}
	}

	// ── Build provider list ──────────────────────────────────────────────────
	providers, primaryProvider := buildProviders(strategy, providerName, openAIKey, anthropicKey, geminiKey, logger)
	if len(providers) == 0 {
		logger.Fatal("model-gateway-agent: no providers configured")
	}

	// ── Build guardrails pipeline ────────────────────────────────────────────
	sanitizerCfg := guardrails.DefaultSanitizerConfig()
	sanitizerCfg.MaxPromptLength = maxPromptLength
	pipeline := guardrails.NewPipeline(sanitizerCfg, guardrails.ValidatorConfig{
		MinConfidenceThreshold: minConfidence,
	})

	// ── Build tool intent checker ────────────────────────────────────────────
	toolPolicyPath := envOr("OPENGUARD_TOOL_POLICY_PATH", "policies/agent-tools.yaml")
	toolChecker, err := toolcheck.New(toolcheck.Config{PolicyPath: toolPolicyPath}, logger)
	if err != nil {
		logger.Warn("model-gateway-agent: could not load tool policy, using fail-secure deny-all default",
			zap.String("path", toolPolicyPath), zap.Error(err))
		fallback, ferr := toolcheck.New(toolcheck.Config{}, logger)
		if ferr != nil {
			logger.Fatal("model-gateway-agent: failed to initialize tool intent checker", zap.Error(ferr))
		}
		toolChecker = fallback
	}

	// ── Build rate limiter ───────────────────────────────────────────────────
	limiter := newRateLimiter(rateLimitRPM)

	// ── Build router ─────────────────────────────────────────────────────────
	router := routing.NewRouter(providers, routing.Config{PrimaryProviderIndex: 0}, logger)

	// ── Connect to NATS ──────────────────────────────────────────────────────
	natsUser := os.Getenv("OPENGUARD_NATS_USER")
	natsPassword := os.Getenv("OPENGUARD_NATS_PASSWORD")
	natsCreds := os.Getenv("OPENGUARD_NATS_CREDS_FILE")
	natsCACert := os.Getenv("OPENGUARD_NATS_CA_CERT")

	var natsOpts []nats.Option
	if natsCreds != "" {
		natsOpts = append(natsOpts, nats.UserCredentials(natsCreds))
	} else if natsUser != "" {
		natsOpts = append(natsOpts, nats.UserInfo(natsUser, natsPassword))
	}
	if natsCACert != "" {
		natsOpts = append(natsOpts, nats.RootCAs(natsCACert))
	}

	nc, err := nats.Connect(natsURL, natsOpts...)
	if err != nil {
		logger.Fatal("model-gateway-agent: failed to connect to NATS",
			zap.String("nats_url", natsURL), zap.Error(err))
	}
	defer nc.Drain() //nolint:errcheck

	// ── Build audit ledger ───────────────────────────────────────────────────
	auditPath := envOr("OPENGUARD_AUDIT_PATH", audit.DefaultStoragePath)
	auditLedger := audit.New(audit.Config{StoragePath: auditPath}, nc, logger)
	if err := auditLedger.Open(); err != nil {
		logger.Warn("model-gateway-agent: could not open audit ledger file",
			zap.String("path", auditPath), zap.Error(err))
	}
	defer auditLedger.Close() //nolint:errcheck

	logger.Info("model-gateway-agent: started",
		zap.String("provider", primaryProvider),
		zap.String("strategy", strategy),
		zap.String("nats_url", natsURL),
		zap.String("model_topic", modelTopic),
		zap.String("result_topic", resultTopic),
	)

	// ── Subscribe to model requests ──────────────────────────────────────────
	sub, err := nc.Subscribe(modelTopic, func(msg *nats.Msg) {
		handleMessage(msg, nc, resultTopic, pipeline, toolChecker, router, auditLedger, strategy, sigSecret, limiter, logger)
	})
	if err != nil {
		logger.Fatal("model-gateway-agent: failed to subscribe", zap.String("topic", modelTopic), zap.Error(err))
	}
	defer sub.Unsubscribe() //nolint:errcheck

	// ── Prometheus metrics endpoint (localhost only) ──────────────────────────
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: "127.0.0.1:9093", Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Warn("model-gateway-agent: metrics server error", zap.Error(err))
		}
	}()

	// ── Health-check loop ────────────────────────────────────────────────────
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			for _, p := range providers {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if err := p.HealthCheck(ctx); err != nil {
					logger.Warn("model-gateway-agent: health check failed",
						zap.String("provider", p.ProviderName()), zap.Error(err))
				} else {
					logger.Info("model-gateway-agent: health check ok",
						zap.String("provider", p.ProviderName()))
				}
				cancel()
			}
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("model-gateway-agent: shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("model-gateway-agent: metrics server shutdown error", zap.Error(err))
	}
	logger.Info("model-gateway-agent: stopped")
}

// verifyHMAC verifies the HMAC-SHA256 signature of a JSON message payload.
// The canonical form is the JSON payload with the "signature" field removed,
// so the sender and receiver compute HMAC over identical data.
func verifyHMAC(data []byte, signature, secret string) bool {
	// Strip the signature field from the JSON before computing HMAC.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return false
	}
	delete(raw, "signature")
	canonical, err := json.Marshal(raw)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(canonical)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

// handleMessage processes a single NATS message through the 7-stage pipeline:
// sanitize → tool check → route → validate → code scan → audit → publish.
func handleMessage(
	msg *nats.Msg,
	nc *nats.Conn,
	resultTopic string,
	pipeline *guardrails.Pipeline,
	toolChecker *toolcheck.ToolIntentChecker,
	router *routing.Router,
	auditLedger *audit.AuditLedger,
	routingStrategy string,
	sigSecret string,
	limiter *rateLimiter,
	logger *zap.Logger,
) {
	// Verify HMAC signature when a secret is configured.
	if sigSecret != "" {
		var raw map[string]interface{}
		if err := json.Unmarshal(msg.Data, &raw); err != nil {
			logger.Warn("model-gateway-agent: HMAC: failed to parse message", zap.Error(err))
			publishError(nc, resultTopic, "", "signature verification failed", logger)
			return
		}
		sig, _ := raw["signature"].(string)
		// Compute HMAC over the canonical payload (signature field excluded).
		if !verifyHMAC(msg.Data, sig, sigSecret) {
			logger.Warn("model-gateway-agent: HMAC verification failed")
			publishError(nc, resultTopic, "", "signature verification failed", logger)
			return
		}
	}

	var req modelRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		logger.Warn("model-gateway-agent: failed to deserialize request", zap.Error(err))
		publishError(nc, resultTopic, "", fmt.Sprintf("deserialize: %v", err), logger)
		return
	}

	// Require non-empty agent_id and event_id.
	if req.AgentID == "" || req.EventID == "" {
		logger.Warn("model-gateway-agent: missing agent_id or event_id",
			zap.String("agent_id", req.AgentID),
			zap.String("event_id", req.EventID))
		publishError(nc, resultTopic, req.EventID, "agent_id and event_id are required", logger)
		return
	}

	// Validate and floor risk_level.
	switch req.RiskLevel {
	case string(mg.RiskLow), string(mg.RiskMedium), string(mg.RiskHigh), string(mg.RiskCritical):
	// valid
	default:
		req.RiskLevel = string(mg.RiskLow)
	}

	// Per-agent rate limiting.
	if !limiter.allow(req.AgentID) {
		logger.Warn("model-gateway-agent: rate limit exceeded",
			zap.String("agent_id", req.AgentID))
		publishError(nc, resultTopic, req.EventID, "rate limit exceeded", logger)
		return
	}

	// Stage 1: Sanitize prompt.
	sanitized, redactions, err := pipeline.SanitizePrompt(req.Prompt)
	if err != nil {
		logger.Warn("model-gateway-agent: prompt blocked",
			zap.String("event_id", req.EventID), zap.Error(err))
		publishError(nc, resultTopic, req.EventID, fmt.Sprintf("prompt blocked: %v", err), logger)
		return
	}

	// Stage 2: Tool intent check.
	if len(req.ToolCalls) > 0 {
		if err := toolChecker.Check(req.AgentID, req.ToolCalls); err != nil {
			logger.Warn("model-gateway-agent: tool intent check failed",
				zap.String("event_id", req.EventID),
				zap.String("agent_id", req.AgentID),
				zap.String("indicator", "tool_use_outside_scope"),
				zap.Error(err))
			publishError(nc, resultTopic, req.EventID, fmt.Sprintf("tool check: %v", err), logger)
			return
		}
	}

	// Stage 3: Dispatch to router.
	eventCtx := mg.EventContext{
		EventID:    req.EventID,
		Domain:     req.Domain,
		RawPayload: sanitized,
		Indicators: req.Indicators,
		Timestamp:  time.Now(),
	}
	riskLevel := mg.RiskLevel(req.RiskLevel)
	if riskLevel == "" {
		riskLevel = mg.RiskLow
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dispatchStart := time.Now()
	result, err := router.Route(ctx, eventCtx, riskLevel)
	latencyMS := time.Since(dispatchStart).Milliseconds()
	if err != nil {
		logger.Warn("model-gateway-agent: router error",
			zap.String("event_id", req.EventID), zap.Error(err))
		publishError(nc, resultTopic, req.EventID, fmt.Sprintf("router: %v", err), logger)
		return
	}

	// Stage 4: Validate output.
	if err := pipeline.ValidateAnalysis(result); err != nil {
		logger.Warn("model-gateway-agent: output validation failed",
			zap.String("event_id", req.EventID), zap.Error(err))
		publishError(nc, resultTopic, req.EventID, fmt.Sprintf("validation: %v", err), logger)
		return
	}

	// Stage 5: Code sandbox scan.
	scanResult := pipeline.ScanCode(result.Summary)
	if scanResult.ContainsCode {
		logger.Warn("model-gateway-agent: executable code in model output",
			zap.String("event_id", req.EventID),
			zap.String("indicator", "executable_code_in_model_output"),
			zap.Strings("patterns", scanResult.Patterns))
		result.Summary = scanResult.Sanitized
	}

	// Stage 6: Audit ledger record.
	auditEntry := audit.AuditEntry{
		AgentID:         req.AgentID,
		Provider:        result.ProviderName,
		InputHash:       audit.HashString(sanitized),
		OutputHash:      audit.HashString(result.Summary),
		LatencyMS:       latencyMS,
		RiskLevel:       string(riskLevel),
		RoutingStrategy: routingStrategy,
	}
	if err := auditLedger.Record(ctx, auditEntry); err != nil {
		logger.Warn("model-gateway-agent: audit record failed",
			zap.String("event_id", req.EventID), zap.Error(err))
	}

	// Stage 7: Publish result.
	resp := modelResponse{
		EventID:    req.EventID,
		Result:     result,
		Redactions: redactions,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		logger.Warn("model-gateway-agent: failed to marshal response", zap.Error(err))
		return
	}
	if err := nc.Publish(resultTopic, data); err != nil {
		logger.Warn("model-gateway-agent: failed to publish result",
			zap.String("event_id", req.EventID), zap.Error(err))
	}
}

// publishError publishes an error response to the result topic.
func publishError(nc *nats.Conn, topic, eventID, errMsg string, logger *zap.Logger) {
	resp := modelResponse{EventID: eventID, Error: errMsg}
	data, err := json.Marshal(resp)
	if err != nil {
		logger.Warn("model-gateway-agent: failed to marshal error response", zap.Error(err))
		return
	}
	if err := nc.Publish(topic, data); err != nil {
		logger.Warn("model-gateway-agent: failed to publish error", zap.Error(err))
	}
}

// buildProviders constructs the appropriate model provider(s) based on the
// configured strategy and provider name.
func buildProviders(
	strategy, providerName, openAIKey, anthropicKey, geminiKey string,
	logger *zap.Logger,
) ([]mg.ModelProvider, string) {
	// For quorum strategy, instantiate all providers that have API keys.
	if strategy == "quorum" {
		var providers []mg.ModelProvider
		if openAIKey != "" {
			providers = append(providers, codex.NewCodexProvider(codex.Config{APIKey: openAIKey}, logger))
		}
		if anthropicKey != "" {
			providers = append(providers, claude.NewClaudeProvider(claude.Config{APIKey: anthropicKey}, logger))
		}
		if geminiKey != "" {
			providers = append(providers, gemini.NewGeminiProvider(gemini.Config{APIKey: geminiKey}, logger))
		}
		primary := providerName
		if len(providers) > 0 {
			primary = providers[0].ProviderName()
		}
		return providers, primary
	}

	// For single / fallback strategy, use the named primary provider.
	switch providerName {
	case "claude":
		p := claude.NewClaudeProvider(claude.Config{APIKey: anthropicKey}, logger)
		return []mg.ModelProvider{p}, p.ProviderName()
	case "gemini":
		p := gemini.NewGeminiProvider(gemini.Config{APIKey: geminiKey}, logger)
		return []mg.ModelProvider{p}, p.ProviderName()
	default: // "codex"
		p := codex.NewCodexProvider(codex.Config{APIKey: openAIKey}, logger)
		return []mg.ModelProvider{p}, p.ProviderName()
	}
}

// envOr returns the value of the environment variable key, or fallback if unset.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
