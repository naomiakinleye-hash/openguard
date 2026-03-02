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

	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	commsguard "github.com/DiniMuhd7/openguard/adapters/commsguard"
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

	contentAnalysis := os.Getenv("COMMSGUARD_ENABLE_CONTENT_ANALYSIS")
	if strings.EqualFold(contentAnalysis, "false") {
		cfg.EnableContentAnalysis = false
	} else {
		cfg.EnableContentAnalysis = true
	}

	cfg.BulkMessageThreshold = 20
	cfg.BulkMessageWindow = 60 * time.Second

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
