// main.go — ModelGuard Agent (standalone binary)
// Delegates all processing to the model-gateway/agent library package.
// The standalone binary additionally exposes Prometheus metrics on :9093.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	nats "github.com/nats-io/nats.go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/DiniMuhd7/openguard/model-gateway/agent"
	"github.com/DiniMuhd7/openguard/model-gateway/audit"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic("model-gateway-agent: failed to init logger: " + err.Error())
	}
	defer logger.Sync() //nolint:errcheck

	// ── Build config from environment ────────────────────────────────────────
	cfg := agent.DefaultConfig()
	cfg.ModelTopic = envOr("OPENGUARD_MODEL_TOPIC", cfg.ModelTopic)
	cfg.ResultTopic = envOr("OPENGUARD_RESULT_TOPIC", cfg.ResultTopic)
	cfg.ConfigTopic = envOr("OPENGUARD_CONFIG_TOPIC", cfg.ConfigTopic)
	cfg.ProviderName = envOr("OPENGUARD_PROVIDER", cfg.ProviderName)
	cfg.Strategy = envOr("OPENGUARD_RISK_STRATEGY", cfg.Strategy)
	cfg.OpenAIKey = os.Getenv("OPENGUARD_OPENAI_API_KEY")
	cfg.AnthropicKey = os.Getenv("OPENGUARD_ANTHROPIC_API_KEY")
	cfg.GeminiKey = os.Getenv("OPENGUARD_GEMINI_API_KEY")
	cfg.SigSecret = os.Getenv("OPENGUARD_MSG_HMAC_SECRET")
	cfg.ToolPolicyPath = envOr("OPENGUARD_TOOL_POLICY_PATH", cfg.ToolPolicyPath)
	cfg.AuditPath = envOr("OPENGUARD_AUDIT_PATH", audit.DefaultStoragePath)

	if v := os.Getenv("OPENGUARD_RATE_LIMIT_RPM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.RateLimitRPM = n
		}
	}
	if v := os.Getenv("OPENGUARD_MIN_CONFIDENCE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.MinConfidence = f
		} else {
			logger.Warn("model-gateway-agent: invalid OPENGUARD_MIN_CONFIDENCE", zap.Error(err))
		}
	}
	if v := os.Getenv("OPENGUARD_MAX_PROMPT_LENGTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MaxPromptLength = n
		} else {
			logger.Warn("model-gateway-agent: invalid OPENGUARD_MAX_PROMPT_LENGTH", zap.Error(err))
		}
	}

	// ── Connect to NATS ──────────────────────────────────────────────────────
	natsURL := envOr("OPENGUARD_NATS_URL", "nats://localhost:4222")
	var natsOpts []nats.Option
	if creds := os.Getenv("OPENGUARD_NATS_CREDS_FILE"); creds != "" {
		natsOpts = append(natsOpts, nats.UserCredentials(creds))
	} else if user := os.Getenv("OPENGUARD_NATS_USER"); user != "" {
		natsOpts = append(natsOpts, nats.UserInfo(user, os.Getenv("OPENGUARD_NATS_PASSWORD")))
	}
	if ca := os.Getenv("OPENGUARD_NATS_CA_CERT"); ca != "" {
		natsOpts = append(natsOpts, nats.RootCAs(ca))
	}

	nc, err := nats.Connect(natsURL, natsOpts...)
	if err != nil {
		logger.Fatal("model-gateway-agent: failed to connect to NATS",
			zap.String("nats_url", natsURL), zap.Error(err))
	}
	defer nc.Drain() //nolint:errcheck

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ── Start model-gateway agent ────────────────────────────────────────────
	stop, err := agent.Run(ctx, nc, cfg, logger)
	if err != nil {
		logger.Fatal("model-gateway-agent: failed to start", zap.Error(err))
	}
	defer stop()

	// ── Prometheus metrics endpoint (localhost only) ──────────────────────────
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{Addr: "127.0.0.1:9093", Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Warn("model-gateway-agent: metrics server error", zap.Error(err))
		}
	}()

	// ── Graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("model-gateway-agent: shutting down")
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("model-gateway-agent: metrics server shutdown error", zap.Error(err))
	}
	logger.Info("model-gateway-agent: stopped")
}


// envOr returns the value of the environment variable key, or fallback if unset.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

