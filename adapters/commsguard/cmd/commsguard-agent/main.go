// Command commsguard-agent is the CommsGuard multi-channel communications sensor.
// It monitors WhatsApp, Telegram, Facebook Messenger, Twilio SMS/Voice, and
// Twitter/X for phishing, credential harvesting, data exfiltration, and
// social engineering patterns.
package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	commsguard "github.com/DiniMuhd7/openguard/adapters/commsguard"
	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic("failed to create logger: " + err.Error())
	}
	defer logger.Sync() //nolint:errcheck

	cfg := buildConfig()
	logActiveChannels(logger, cfg)

	sensor, err := commsguard.NewCommsGuardSensor(cfg, logger)
	if err != nil {
		logger.Fatal("commsguard-agent: failed to create sensor", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := sensor.Start(ctx); err != nil {
		logger.Fatal("commsguard-agent: failed to start sensor", zap.Error(err))
	}

	logger.Info("commsguard-agent: started",
		zap.String("listen_addr", cfg.ListenAddr),
		zap.String("nats_url", cfg.NATSUrl),
		zap.String("topic", cfg.RawEventTopic),
	)

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("commsguard-agent: shutting down")
	if err := sensor.Stop(); err != nil {
		logger.Warn("commsguard-agent: stop error", zap.Error(err))
	}
	logger.Info("commsguard-agent: stopped")
}

// buildConfig constructs a Config from environment variables.
func buildConfig() common.Config {
	cfg := common.DefaultConfig()

	if v := os.Getenv("NATS_URL"); v != "" {
		cfg.NATSUrl = v
	}
	if v := os.Getenv("COMMSGUARD_TOPIC"); v != "" {
		cfg.RawEventTopic = v
	}
	if v := os.Getenv("COMMSGUARD_LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}

	cfg.WhatsAppAppSecret = os.Getenv("WHATSAPP_APP_SECRET")
	cfg.WhatsAppVerifyToken = os.Getenv("WHATSAPP_VERIFY_TOKEN")
	cfg.TelegramBotToken = os.Getenv("TELEGRAM_BOT_TOKEN")
	cfg.MessengerAppSecret = os.Getenv("MESSENGER_APP_SECRET")
	cfg.MessengerVerifyToken = os.Getenv("MESSENGER_VERIFY_TOKEN")
	cfg.TwilioAuthToken = os.Getenv("TWILIO_AUTH_TOKEN")
	cfg.TwilioAccountSID = os.Getenv("TWILIO_ACCOUNT_SID")
	cfg.TwitterBearerToken = os.Getenv("TWITTER_BEARER_TOKEN")
	cfg.TwitterWebhookSecret = os.Getenv("TWITTER_WEBHOOK_SECRET")

	// Tunnel config — set COMMSGUARD_TUNNEL_MODE to "ngrok" or "cloudflared" to
	// expose the local webhook server to the internet automatically.
	cfg.TunnelMode = os.Getenv("COMMSGUARD_TUNNEL_MODE")
	cfg.NgrokAuthToken = os.Getenv("NGROK_AUTHTOKEN")

	contentAnalysis := os.Getenv("COMMSGUARD_ENABLE_CONTENT_ANALYSIS")
	if strings.EqualFold(contentAnalysis, "false") {
		cfg.EnableContentAnalysis = false
	} else {
		cfg.EnableContentAnalysis = true
	}

	// ── Model-gateway AI enrichment ──────────────────────────────────────────
	// COMMSGUARD_MODEL_GATEWAY_ENABLED=true enables semantic AI analysis of
	// messages via the model-gateway agent (must be running and reachable on NATS).
	if strings.EqualFold(os.Getenv("COMMSGUARD_MODEL_GATEWAY_ENABLED"), "true") {
		cfg.ModelGatewayEnabled = true
	}
	if v := os.Getenv("COMMSGUARD_MODEL_GATEWAY_TOPIC"); v != "" {
		cfg.ModelGatewayTopic = v
	}
	if v := os.Getenv("COMMSGUARD_MODEL_GATEWAY_AGENT_ID"); v != "" {
		cfg.ModelGatewayAgentID = v
	}
	if v := os.Getenv("COMMSGUARD_MODEL_GATEWAY_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.ModelGatewayTimeout = d
		}
	}

	// ── Cross-channel correlation window ─────────────────────────────────────
	// COMMSGUARD_CROSS_CHANNEL_WINDOW sets the look-back period for detecting
	// the same attacker across multiple channels (default: 24h).
	if v := os.Getenv("COMMSGUARD_CROSS_CHANNEL_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.CrossChannelWindow = d
		}
	}

	return cfg
}

// logActiveChannels logs which channels are enabled based on non-empty credentials.
func logActiveChannels(logger *zap.Logger, cfg common.Config) {
	channels := []string{}
	if cfg.WhatsAppAppSecret != "" || cfg.WhatsAppVerifyToken != "" {
		channels = append(channels, "whatsapp")
	}
	if cfg.TelegramBotToken != "" {
		channels = append(channels, "telegram")
	}
	if cfg.MessengerAppSecret != "" || cfg.MessengerVerifyToken != "" {
		channels = append(channels, "messenger")
	}
	if cfg.TwilioAuthToken != "" || cfg.TwilioAccountSID != "" {
		channels = append(channels, "twilio")
	}
	if cfg.TwitterBearerToken != "" || cfg.TwitterWebhookSecret != "" {
		channels = append(channels, "twitter")
	}

	if len(channels) == 0 {
		logger.Warn("commsguard-agent: no channels configured — set channel credentials via environment variables")
	} else {
		logger.Info("commsguard-agent: active channels", zap.Strings("channels", channels))
	}
}
