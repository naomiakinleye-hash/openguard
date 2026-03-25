// Package agent provides the embeddable model-gateway runtime.
//
// Importing this package lets any Go binary (e.g. the monolithic openguard
// binary) start the model-gateway agent in-process with a single function
// call, while the standalone model-gateway-agent binary still works unchanged.
package agent

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	nats "github.com/nats-io/nats.go"
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

// Config holds all runtime configuration for the model-gateway agent.
type Config struct {
	// ModelTopic is the NATS subject for incoming model requests.
	// Defaults to "openguard.modelguard.requests".
	ModelTopic string
	// ResultTopic is the NATS subject for publishing results when the caller
	// does not use NATS request-reply. Defaults to "openguard.modelguard.results".
	ResultTopic string
	// ConfigTopic is the NATS subject for live provider config updates.
	// Defaults to "openguard.modelguard.config".
	ConfigTopic string

	// ProviderName selects the primary AI provider: "codex", "claude", "gemini".
	// Defaults to "codex".
	ProviderName string
	// Strategy controls multi-provider routing: "single", "fallback", "quorum".
	// Defaults to "single".
	Strategy string

	// API keys for each supported provider.
	OpenAIKey    string
	AnthropicKey string
	GeminiKey    string

	// SigSecret is an optional HMAC-SHA256 secret used to verify message signatures.
	SigSecret string

	// ToolPolicyPath is the path to the agent-tools YAML policy file.
	// Defaults to "policies/agent-tools.yaml".
	ToolPolicyPath string
	// AuditPath is the path to the model-gateway audit NDJSON file.
	// Defaults to the value of audit.DefaultStoragePath.
	AuditPath string

	// RateLimitRPM is the per-agent rate limit in requests per minute.
	// Defaults to 60.
	RateLimitRPM int
	// MaxPromptLength is the maximum allowed prompt length in bytes.
	// Defaults to 8192.
	MaxPromptLength int
	// MinConfidence is the minimum acceptable model confidence threshold (0–1).
	MinConfidence float64
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() Config {
	return Config{
		ModelTopic:      "openguard.modelguard.requests",
		ResultTopic:     "openguard.modelguard.results",
		ConfigTopic:     "openguard.modelguard.config",
		ProviderName:    "codex",
		Strategy:        "single",
		ToolPolicyPath:  "policies/agent-tools.yaml",
		AuditPath:       audit.DefaultStoragePath,
		RateLimitRPM:    60,
		MaxPromptLength: 8192,
	}
}

// Run starts the model-gateway agent on the given NATS connection and returns
// a stop function. The stop function blocks until all in-flight handlers have
// returned and all subscriptions are drained.
//
// Run returns (nil, nil) with a warning log when no API key is configured so
// that callers can treat the gateway as optional without fatally erroring.
func Run(ctx context.Context, nc *nats.Conn, cfg Config, logger *zap.Logger) (func(), error) {
	if cfg.OpenAIKey == "" && cfg.AnthropicKey == "" && cfg.GeminiKey == "" {
		logger.Warn("model-gateway: no API key configured — AI enrichment is disabled",
			zap.String("hint", "set OPENGUARD_OPENAI_API_KEY, OPENGUARD_ANTHROPIC_API_KEY, or OPENGUARD_GEMINI_API_KEY"))
		return func() {}, nil
	}

	// ── Build providers ──────────────────────────────────────────────────────
	providers, primaryProvider := buildProviders(cfg.Strategy, cfg.ProviderName,
		cfg.OpenAIKey, cfg.AnthropicKey, cfg.GeminiKey, logger)
	if len(providers) == 0 {
		return nil, fmt.Errorf("model-gateway: no providers could be initialised")
	}

	// ── Build guardrails pipeline ────────────────────────────────────────────
	sanitizerCfg := guardrails.DefaultSanitizerConfig()
	sanitizerCfg.MaxPromptLength = cfg.MaxPromptLength
	pipeline := guardrails.NewPipeline(sanitizerCfg, guardrails.ValidatorConfig{
		MinConfidenceThreshold: cfg.MinConfidence,
	})

	// ── Build tool intent checker ────────────────────────────────────────────
	toolChecker, err := toolcheck.New(toolcheck.Config{PolicyPath: cfg.ToolPolicyPath}, logger)
	if err != nil {
		logger.Warn("model-gateway: could not load tool policy, using fail-secure deny-all default",
			zap.String("path", cfg.ToolPolicyPath), zap.Error(err))
		fallback, ferr := toolcheck.New(toolcheck.Config{}, logger)
		if ferr != nil {
			return nil, fmt.Errorf("model-gateway: failed to init tool checker: %w", ferr)
		}
		toolChecker = fallback
	}

	// ── Build rate limiter ───────────────────────────────────────────────────
	limiter := newRateLimiter(cfg.RateLimitRPM)

	// ── Build router ─────────────────────────────────────────────────────────
	router := routing.NewRouter(providers, routing.Config{PrimaryProviderIndex: 0}, logger)
	var activeRouter atomic.Pointer[routing.Router]
	activeRouter.Store(router)

	// ── Open audit ledger ────────────────────────────────────────────────────
	auditLedger := audit.New(audit.Config{StoragePath: cfg.AuditPath}, nc, logger)
	if err := auditLedger.Open(); err != nil {
		logger.Warn("model-gateway: could not open audit ledger",
			zap.String("path", cfg.AuditPath), zap.Error(err))
	}

	// ── Subscribe to model requests ──────────────────────────────────────────
	resultTopic := cfg.ResultTopic
	sigSecret := cfg.SigSecret
	strategy := cfg.Strategy

	sub, err := nc.Subscribe(cfg.ModelTopic, func(msg *nats.Msg) {
		replyTo := resultTopic
		if msg.Reply != "" {
			replyTo = msg.Reply
		}
		handleMessage(msg, nc, replyTo, pipeline, toolChecker, &activeRouter,
			auditLedger, strategy, sigSecret, limiter, logger)
	})
	if err != nil {
		auditLedger.Close() //nolint:errcheck
		return nil, fmt.Errorf("model-gateway: subscribe to %s: %w", cfg.ModelTopic, err)
	}

	// ── Subscribe to live config updates ─────────────────────────────────────
	configSub, configErr := nc.Subscribe(cfg.ConfigTopic, func(msg *nats.Msg) {
		handleConfigUpdate(msg, &activeRouter, logger)
	})
	if configErr != nil {
		logger.Warn("model-gateway: failed to subscribe to config topic — live provider updates disabled",
			zap.String("topic", cfg.ConfigTopic), zap.Error(configErr))
	}

	logger.Info("model-gateway: running in-process",
		zap.String("provider", primaryProvider),
		zap.String("strategy", strategy),
		zap.String("model_topic", cfg.ModelTopic),
		zap.String("result_topic", resultTopic),
	)

	stop := func() {
		_ = sub.Drain()
		if configSub != nil {
			_ = configSub.Unsubscribe()
		}
		auditLedger.Close() //nolint:errcheck
	}
	return stop, nil
}

// ── private types ─────────────────────────────────────────────────────────────

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

// modelConfigUpdate is the JSON payload for live provider config updates.
type modelConfigUpdate struct {
	Provider string `json:"provider"`
	APIKey   string `json:"api_key"`
}

// rateLimiter tracks per-agent call counts within a rolling minute window.
type rateLimiter struct {
	mu       sync.Mutex
	counts   map[string][]time.Time
	limitRPM int
}

func newRateLimiter(limitRPM int) *rateLimiter {
	return &rateLimiter{counts: make(map[string][]time.Time), limitRPM: limitRPM}
}

func (rl *rateLimiter) allow(agentID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	times := rl.counts[agentID]
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

// ── private helpers ───────────────────────────────────────────────────────────

func buildProviders(strategy, providerName, openAIKey, anthropicKey, geminiKey string, logger *zap.Logger) ([]mg.ModelProvider, string) {
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

func handleConfigUpdate(msg *nats.Msg, activeRouter *atomic.Pointer[routing.Router], logger *zap.Logger) {
	var update modelConfigUpdate
	if err := json.Unmarshal(msg.Data, &update); err != nil {
		logger.Warn("model-gateway: invalid config update — ignoring", zap.Error(err))
		return
	}
	if update.APIKey == "" {
		logger.Info("model-gateway: provider disconnected in Model Settings — router unchanged",
			zap.String("provider", update.Provider))
		return
	}
	var p mg.ModelProvider
	switch update.Provider {
	case "codex":
		p = codex.NewCodexProvider(codex.Config{APIKey: update.APIKey}, logger)
	case "claude":
		p = claude.NewClaudeProvider(claude.Config{APIKey: update.APIKey}, logger)
	case "gemini":
		p = gemini.NewGeminiProvider(gemini.Config{APIKey: update.APIKey}, logger)
	default:
		logger.Warn("model-gateway: unknown provider in config update — ignoring",
			zap.String("provider", update.Provider))
		return
	}
	newRouter := routing.NewRouter([]mg.ModelProvider{p}, routing.Config{PrimaryProviderIndex: 0}, logger)
	activeRouter.Store(newRouter)
	logger.Info("model-gateway: hot-swapped to provider from Model Settings",
		zap.String("provider", update.Provider))
}

func handleMessage(
	msg *nats.Msg,
	nc *nats.Conn,
	resultTopic string,
	pipeline *guardrails.Pipeline,
	toolChecker *toolcheck.ToolIntentChecker,
	activeRouter *atomic.Pointer[routing.Router],
	auditLedger *audit.AuditLedger,
	routingStrategy string,
	sigSecret string,
	limiter *rateLimiter,
	logger *zap.Logger,
) {
	if sigSecret != "" {
		var raw map[string]interface{}
		if err := json.Unmarshal(msg.Data, &raw); err != nil {
			logger.Warn("model-gateway: HMAC: failed to parse message", zap.Error(err))
			publishError(nc, resultTopic, "", "signature verification failed", logger)
			return
		}
		sig, _ := raw["signature"].(string)
		if !verifyHMAC(msg.Data, sig, sigSecret) {
			logger.Warn("model-gateway: HMAC verification failed")
			publishError(nc, resultTopic, "", "signature verification failed", logger)
			return
		}
	}

	var req modelRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		logger.Warn("model-gateway: failed to deserialize request", zap.Error(err))
		publishError(nc, resultTopic, "", fmt.Sprintf("deserialize: %v", err), logger)
		return
	}

	if req.AgentID == "" || req.EventID == "" {
		logger.Warn("model-gateway: missing agent_id or event_id",
			zap.String("agent_id", req.AgentID), zap.String("event_id", req.EventID))
		publishError(nc, resultTopic, req.EventID, "agent_id and event_id are required", logger)
		return
	}

	switch req.RiskLevel {
	case string(mg.RiskLow), string(mg.RiskMedium), string(mg.RiskHigh), string(mg.RiskCritical):
	default:
		req.RiskLevel = string(mg.RiskLow)
	}

	if !limiter.allow(req.AgentID) {
		logger.Warn("model-gateway: rate limit exceeded", zap.String("agent_id", req.AgentID))
		publishError(nc, resultTopic, req.EventID, "rate limit exceeded", logger)
		return
	}

	sanitized, redactions, err := pipeline.SanitizePrompt(req.Prompt)
	if err != nil {
		logger.Warn("model-gateway: prompt blocked",
			zap.String("event_id", req.EventID), zap.Error(err))
		publishError(nc, resultTopic, req.EventID, fmt.Sprintf("prompt blocked: %v", err), logger)
		return
	}

	if len(req.ToolCalls) > 0 {
		if err := toolChecker.Check(req.AgentID, req.ToolCalls); err != nil {
			logger.Warn("model-gateway: tool intent check failed",
				zap.String("event_id", req.EventID), zap.String("agent_id", req.AgentID), zap.Error(err))
			publishError(nc, resultTopic, req.EventID, fmt.Sprintf("tool check: %v", err), logger)
			return
		}
	}

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

	router := activeRouter.Load()
	dispatchStart := time.Now()
	result, err := router.Route(ctx, eventCtx, riskLevel)
	latencyMS := time.Since(dispatchStart).Milliseconds()
	if err != nil {
		logger.Warn("model-gateway: router error",
			zap.String("event_id", req.EventID), zap.Error(err))
		publishError(nc, resultTopic, req.EventID, fmt.Sprintf("router: %v", err), logger)
		return
	}

	if err := pipeline.ValidateAnalysis(result); err != nil {
		logger.Warn("model-gateway: output validation failed",
			zap.String("event_id", req.EventID), zap.Error(err))
		publishError(nc, resultTopic, req.EventID, fmt.Sprintf("validation: %v", err), logger)
		return
	}

	scanResult := pipeline.ScanCode(result.Summary)
	if scanResult.ContainsCode {
		logger.Warn("model-gateway: executable code in model output",
			zap.String("event_id", req.EventID), zap.Strings("patterns", scanResult.Patterns))
		result.Summary = scanResult.Sanitized
	}

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
		logger.Warn("model-gateway: audit record failed",
			zap.String("event_id", req.EventID), zap.Error(err))
	}

	resp := modelResponse{EventID: req.EventID, Result: result, Redactions: redactions}
	data, err := json.Marshal(resp)
	if err != nil {
		logger.Warn("model-gateway: failed to marshal response", zap.Error(err))
		return
	}
	if err := nc.Publish(resultTopic, data); err != nil {
		logger.Warn("model-gateway: failed to publish result",
			zap.String("event_id", req.EventID), zap.Error(err))
	}
}

func publishError(nc *nats.Conn, topic, eventID, errMsg string, logger *zap.Logger) {
	resp := modelResponse{EventID: eventID, Error: errMsg}
	data, err := json.Marshal(resp)
	if err != nil {
		logger.Warn("model-gateway: failed to marshal error response", zap.Error(err))
		return
	}
	if err := nc.Publish(topic, data); err != nil {
		logger.Warn("model-gateway: failed to publish error", zap.Error(err))
	}
}

func verifyHMAC(data []byte, signature, secret string) bool {
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
