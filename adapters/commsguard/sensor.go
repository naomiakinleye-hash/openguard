// Package commsguard provides the multi-channel CommsGuard sensor that aggregates
// all communication channel adapters and routes their HTTP webhooks.
package commsguard

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/commsguard/common"
	"github.com/DiniMuhd7/openguard/adapters/commsguard/messenger"
	"github.com/DiniMuhd7/openguard/adapters/commsguard/telegram"
	"github.com/DiniMuhd7/openguard/adapters/commsguard/tunnel"
	"github.com/DiniMuhd7/openguard/adapters/commsguard/twilio"
	"github.com/DiniMuhd7/openguard/adapters/commsguard/twitter"
	"github.com/DiniMuhd7/openguard/adapters/commsguard/whatsapp"
	"go.uber.org/zap"
)

// CommsGuardSensor aggregates all channel adapters and serves their HTTP webhooks.
type CommsGuardSensor struct {
	cfg       common.Config
	publisher *common.Publisher
	logger    *zap.Logger
	analyzer  *common.ThreatAnalyzer

	whatsapp  *whatsapp.WhatsAppAdapter
	telegram  *telegram.TelegramAdapter
	messenger *messenger.MessengerAdapter
	twilio    *twilio.TwilioAdapter
	twitter   *twitter.TwitterAdapter

	mux    *http.ServeMux
	server *http.Server
	wg     sync.WaitGroup

	tun      *tunnel.Tunnel // non-nil when a tunnel is active
	mu       sync.Mutex
	running  bool
	cancelFn context.CancelFunc
}

// NewCommsGuardSensor creates a new CommsGuardSensor, connecting to NATS and
// initialising only the adapters whose credentials are present in cfg.
func NewCommsGuardSensor(cfg common.Config, logger *zap.Logger) (*CommsGuardSensor, error) {
	if cfg.NATSUrl == "" {
		cfg.NATSUrl = "nats://localhost:4222"
	}
	if cfg.RawEventTopic == "" {
		cfg.RawEventTopic = "openguard.commsguard.raw"
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8090"
	}
	if cfg.BulkMessageThreshold <= 0 {
		cfg.BulkMessageThreshold = 20
	}
	if cfg.BulkMessageWindow <= 0 {
		cfg.BulkMessageWindow = 60 * time.Second
	}

	publisher, err := common.NewPublisher(cfg.NATSUrl, cfg.RawEventTopic, cfg.EnableContentAnalysis, logger)
	if err != nil {
		return nil, fmt.Errorf("commsguard: create publisher: %w", err)
	}

	analyzer := common.NewThreatAnalyzer(cfg.BulkMessageThreshold, cfg.BulkMessageWindow, cfg.EnableContentAnalysis)

	s := &CommsGuardSensor{
		cfg:       cfg,
		publisher: publisher,
		logger:    logger,
		analyzer:  analyzer,
		mux:       http.NewServeMux(),
	}

	// Initialise adapters whose credentials are configured, warn-and-continue on error.
	if cfg.WhatsAppAppSecret != "" || cfg.WhatsAppVerifyToken != "" {
		s.whatsapp = whatsapp.NewWhatsAppAdapter(cfg.WhatsAppAppSecret, cfg.WhatsAppVerifyToken, publisher, analyzer, logger)
		s.mux.Handle("/whatsapp/webhook", s.whatsapp)
		logger.Info("commsguard: whatsapp adapter enabled")
	}

	if cfg.TelegramBotToken != "" {
		s.telegram = telegram.NewTelegramAdapter(cfg.TelegramBotToken, publisher, analyzer, logger)
		s.mux.Handle("/telegram/webhook", s.telegram)
		logger.Info("commsguard: telegram adapter enabled")
	}

	if cfg.MessengerAppSecret != "" || cfg.MessengerVerifyToken != "" {
		s.messenger = messenger.NewMessengerAdapter(cfg.MessengerAppSecret, cfg.MessengerVerifyToken, publisher, analyzer, logger)
		s.mux.Handle("/messenger/webhook", s.messenger)
		logger.Info("commsguard: messenger adapter enabled")
	}

	if cfg.TwilioAuthToken != "" || cfg.TwilioAccountSID != "" {
		s.twilio = twilio.NewTwilioAdapter(cfg.TwilioAuthToken, cfg.TwilioAccountSID, publisher, analyzer, logger)
		s.mux.HandleFunc("/twilio/sms", s.twilio.HandleSMS)
		s.mux.HandleFunc("/twilio/voice", s.twilio.HandleVoice)
		logger.Info("commsguard: twilio adapter enabled")
	}

	if cfg.TwitterWebhookSecret != "" || cfg.TwitterBearerToken != "" {
		s.twitter = twitter.NewTwitterAdapter(cfg.TwitterWebhookSecret, cfg.TwitterBearerToken, publisher, analyzer, logger)
		s.mux.Handle("/twitter/webhook", s.twitter)
		logger.Info("commsguard: twitter adapter enabled")
	}

	s.server = &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: s.mux,
	}

	return s, nil
}

// Start begins the HTTP server and starts all configured adapters.
func (s *CommsGuardSensor) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	innerCtx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel

	// Start all configured adapters.
	for _, adapter := range s.adapters() {
		if err := adapter.Start(innerCtx); err != nil {
			s.logger.Warn("commsguard: adapter start failed",
				zap.String("channel", adapter.Channel()),
				zap.Error(err),
			)
		}
	}

	// Start HTTP server in a goroutine.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.logger.Info("commsguard: HTTP server listening", zap.String("addr", s.cfg.ListenAddr))
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("commsguard: HTTP server error", zap.Error(err))
		}
	}()

	// Start tunnel if configured — wait briefly for the HTTP server to bind first.
	if mode := tunnel.Mode(strings.ToLower(s.cfg.TunnelMode)); mode != tunnel.ModeNone {
		time.Sleep(150 * time.Millisecond)
		tun, err := tunnel.Start(innerCtx, mode, s.cfg.ListenAddr, s.cfg.NgrokAuthToken, s.logger)
		if err != nil {
			s.logger.Error("commsguard: tunnel failed to start — running without tunnel",
				zap.String("mode", s.cfg.TunnelMode),
				zap.Error(err),
			)
		} else {
			s.tun = tun
		}
	}

	s.running = true
	return nil
}

// Stop gracefully shuts down the HTTP server and all adapters.
func (s *CommsGuardSensor) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancelFn != nil {
		s.cancelFn()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(shutdownCtx); err != nil {
		s.logger.Warn("commsguard: HTTP server shutdown error", zap.Error(err))
	}

	for _, adapter := range s.adapters() {
		if err := adapter.Stop(); err != nil {
			s.logger.Warn("commsguard: adapter stop failed",
				zap.String("channel", adapter.Channel()),
				zap.Error(err),
			)
		}
	}

	s.wg.Wait()
	s.publisher.Close()
	if s.tun != nil {
		s.tun.Stop()
		s.tun = nil
	}
	s.running = false
	return nil
}

// HealthCheck verifies that the server is listening and at least one adapter is active.
func (s *CommsGuardSensor) HealthCheck(ctx context.Context) error {
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()

	if !running {
		return fmt.Errorf("commsguard: sensor is not running")
	}

	adapters := s.adapters()
	if len(adapters) == 0 {
		return fmt.Errorf("commsguard: no adapters configured")
	}

	for _, adapter := range adapters {
		if err := adapter.HealthCheck(ctx); err == nil {
			return nil // at least one adapter is healthy
		}
	}
	return fmt.Errorf("commsguard: no healthy adapters")
}

// adapters returns all non-nil adapter instances.
func (s *CommsGuardSensor) adapters() []common.Sensor {
	var result []common.Sensor
	if s.whatsapp != nil {
		result = append(result, s.whatsapp)
	}
	if s.telegram != nil {
		result = append(result, s.telegram)
	}
	if s.messenger != nil {
		result = append(result, s.messenger)
	}
	if s.twilio != nil {
		result = append(result, s.twilio)
	}
	if s.twitter != nil {
		result = append(result, s.twitter)
	}
	return result
}
