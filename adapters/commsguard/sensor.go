// Package commsguard provides the multi-channel CommsGuard sensor that aggregates
// all communication channel adapters and routes their HTTP webhooks.
package commsguard

import (
	"context"
	"encoding/json"
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
	nats "github.com/nats-io/nats.go"
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

	// notifiers is the registry of per-channel Notifier implementations.
	// Keyed by Notifier.Channel(). Populated during NewCommsGuardSensor when
	// the matching channel credentials are configured.
	notifiers map[string]common.Notifier

	mux    *http.ServeMux
	server *http.Server
	wg     sync.WaitGroup

	tun      *tunnel.Tunnel // non-nil when a tunnel is active
	mu       sync.Mutex
	running  bool
	cancelFn context.CancelFunc

	// modelNC is the NATS connection used exclusively by the model-gateway
	// intelligence client. It is separate from the publisher connection so the
	// two can be drained independently on shutdown.
	modelNC *nats.Conn

	// responseNC is the NATS connection used to subscribe to orchestrator
	// response events on cfg.ResponseTopic. Separate from modelNC and the
	// publisher so all three can be drained independently.
	responseNC  *nats.Conn
	responseSub *nats.Subscription
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
	if cfg.ResponseTopic == "" {
		cfg.ResponseTopic = "openguard.commsguard.response"
	}

	publisher, err := common.NewPublisher(cfg.NATSUrl, cfg.RawEventTopic, cfg.EnableContentAnalysis, logger)
	if err != nil {
		return nil, fmt.Errorf("commsguard: create publisher: %w", err)
	}

	// Build the ThreatAnalyzer with optional AI enrichment and cross-channel tracking.
	analyzer := common.NewThreatAnalyzer()

	// Always enable cross-channel correlation (zero-cost when no threats detected).
	crossChannelTracker := common.NewCrossChannelTracker(cfg.CrossChannelWindow, logger)
	analyzer.WithCrossChannelTracker(crossChannelTracker)

	// Conditionally connect to model-gateway for AI enrichment.
	var modelNC *nats.Conn
	if cfg.ModelGatewayEnabled {
		nc, err := nats.Connect(cfg.NATSUrl,
			nats.Name("openguard-commsguard-intel"),
			nats.MaxReconnects(-1),
		)
		if err != nil {
			logger.Warn("commsguard: model-gateway NATS connect failed — AI enrichment disabled",
				zap.String("nats_url", cfg.NATSUrl),
				zap.Error(err),
			)
		} else {
			modelNC = nc
			modelClient := common.NewModelIntelClient(nc, cfg.ModelGatewayTopic, cfg.ModelGatewayTimeout, cfg.ModelGatewayAgentID, logger)
			analyzer.WithModelIntelClient(modelClient)
			logger.Info("commsguard: model-gateway AI enrichment enabled",
				zap.String("topic", cfg.ModelGatewayTopic),
				zap.Duration("timeout", cfg.ModelGatewayTimeout),
			)
		}
	}

	s := &CommsGuardSensor{
		cfg:       cfg,
		publisher: publisher,
		logger:    logger,
		analyzer:  analyzer,
		mux:       http.NewServeMux(),
		modelNC:   modelNC,
		notifiers: make(map[string]common.Notifier),
	}

	// Initialise adapters whose credentials are configured, warn-and-continue on error.
	if cfg.WhatsAppAppSecret != "" || cfg.WhatsAppVerifyToken != "" {
		s.whatsapp = whatsapp.NewWhatsAppAdapter(cfg.WhatsAppAppSecret, cfg.WhatsAppVerifyToken, publisher, analyzer, logger)
		s.mux.Handle("/whatsapp/webhook", s.whatsapp)
		logger.Info("commsguard: whatsapp adapter enabled")

		// Register notifier when WBA send credentials are available.
		if cfg.WhatsAppAccessToken != "" && cfg.WhatsAppPhoneNumberID != "" {
			s.registerNotifier(whatsapp.NewWhatsAppNotifier(cfg.WhatsAppAccessToken, cfg.WhatsAppPhoneNumberID, logger))
			logger.Info("commsguard: whatsapp notifier registered (WBA send path)")
		}
	}

	if cfg.TelegramBotToken != "" {
		s.telegram = telegram.NewTelegramAdapter(cfg.TelegramBotToken, cfg.TelegramWebhookSecret, publisher, analyzer, logger)
		s.mux.Handle("/telegram/webhook", s.telegram)
		logger.Info("commsguard: telegram adapter enabled")

		s.registerNotifier(telegram.NewTelegramNotifier(cfg.TelegramBotToken, logger))
		logger.Info("commsguard: telegram notifier registered")
	}

	if cfg.MessengerAppSecret != "" || cfg.MessengerVerifyToken != "" {
		s.messenger = messenger.NewMessengerAdapter(cfg.MessengerAppSecret, cfg.MessengerVerifyToken, publisher, analyzer, logger)
		s.mux.Handle("/messenger/webhook", s.messenger)
		logger.Info("commsguard: messenger adapter enabled")

		if cfg.MessengerPageAccessToken != "" {
			s.registerNotifier(messenger.NewMessengerNotifier(cfg.MessengerPageAccessToken, logger))
			logger.Info("commsguard: messenger notifier registered")
		}
	}

	if cfg.TwilioAuthToken != "" || cfg.TwilioAccountSID != "" {
		s.twilio = twilio.NewTwilioAdapter(cfg.TwilioAuthToken, cfg.TwilioAccountSID, publisher, analyzer, logger)
		s.mux.HandleFunc("/twilio/sms", s.twilio.HandleSMS)
		s.mux.HandleFunc("/twilio/voice", s.twilio.HandleVoice)
		logger.Info("commsguard: twilio adapter enabled")

		if cfg.TwilioFromNumber != "" {
			s.registerNotifier(twilio.NewTwilioNotifier(cfg.TwilioAccountSID, cfg.TwilioAuthToken, cfg.TwilioFromNumber, logger))
			logger.Info("commsguard: twilio notifier registered")
		}
	}

	if cfg.TwitterWebhookSecret != "" || cfg.TwitterBearerToken != "" {
		s.twitter = twitter.NewTwitterAdapter(cfg.TwitterWebhookSecret, cfg.TwitterBearerToken, publisher, analyzer, logger)
		s.mux.Handle("/twitter/webhook", s.twitter)
		logger.Info("commsguard: twitter adapter enabled")

		if cfg.TwitterBearerToken != "" {
			s.registerNotifier(twitter.NewTwitterNotifier(cfg.TwitterBearerToken, logger))
			logger.Info("commsguard: twitter notifier registered")
		}
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

	// Start orchestrator response subscriber if a NATS connection can be established.
	if len(s.notifiers) > 0 {
		nc, err := nats.Connect(s.cfg.NATSUrl,
			nats.Name("openguard-commsguard-responder"),
			nats.MaxReconnects(-1),
		)
		if err != nil {
			s.logger.Warn("commsguard: response subscriber NATS connect failed — orchestrated notify disabled",
				zap.String("nats_url", s.cfg.NATSUrl),
				zap.Error(err),
			)
		} else {
			sub, err := nc.Subscribe(s.cfg.ResponseTopic, s.handleResponseEvent)
			if err != nil {
				nc.Close()
				s.logger.Warn("commsguard: response subscriber failed",
					zap.String("topic", s.cfg.ResponseTopic),
					zap.Error(err),
				)
			} else {
				s.responseNC = nc
				s.responseSub = sub
				s.logger.Info("commsguard: subscribed to response topic",
					zap.String("topic", s.cfg.ResponseTopic),
				)
			}
		}
	}

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
	if s.modelNC != nil {
		s.modelNC.Drain() //nolint:errcheck
		s.modelNC = nil
	}
	if s.responseNC != nil {
		if s.responseSub != nil {
			s.responseSub.Unsubscribe() //nolint:errcheck
		}
		s.responseNC.Drain() //nolint:errcheck
		s.responseNC = nil
	}
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

// registerNotifier adds a Notifier to the sensor's registry.
func (s *CommsGuardSensor) registerNotifier(n common.Notifier) {
	s.notifiers[n.Channel()] = n
}

// handleResponseEvent is the NATS message handler for orchestrator response
// events published to cfg.ResponseTopic. It decodes the ResponseEvent and
// dispatches Intercept and/or Notify via the registered channel Notifier.
func (s *CommsGuardSensor) handleResponseEvent(msg *nats.Msg) {
	var re common.ResponseEvent
	if err := json.Unmarshal(msg.Data, &re); err != nil {
		s.logger.Warn("commsguard: invalid response event payload",
			zap.Error(err),
			zap.ByteString("data", msg.Data),
		)
		return
	}

	notifier, ok := s.notifiers[re.Channel]
	if !ok {
		s.logger.Debug("commsguard: no notifier for channel — skipping response",
			zap.String("channel", re.Channel),
			zap.String("event_id", re.EventID),
		)
		return
	}

	// Reconstruct a minimal CommsEvent so Notifier implementations have the
	// identifiers they need without requiring the full original event.
	event := &common.CommsEvent{
		Channel:     re.Channel,
		SenderID:    re.SenderID,
		RecipientID: re.RecipientID,
		MessageID:   re.MessageID,
	}

	notifyMsg := re.NotifyMessage
	if notifyMsg == "" {
		notifyMsg = common.DefaultNotifyMessage
	}

	ctx := context.Background()

	// Intercept first (best-effort), then always notify.
	if re.Action == "intercept" || re.Action == "intercept_and_notify" {
		if !s.cfg.InterceptEnabled {
			s.logger.Debug("commsguard: intercept disabled by config",
				zap.String("event_id", re.EventID),
			)
		} else if err := notifier.Intercept(ctx, event); err != nil {
			// ErrInterceptUnsupported is expected for certain channels; log at
			// Debug. Other errors are transient failures; log at Warn.
			if err == common.ErrInterceptUnsupported {
				s.logger.Debug("commsguard: intercept not supported on channel",
					zap.String("channel", re.Channel),
					zap.String("event_id", re.EventID),
				)
			} else {
				s.logger.Warn("commsguard: intercept failed — proceeding to notify",
					zap.String("channel", re.Channel),
					zap.String("event_id", re.EventID),
					zap.Error(err),
				)
			}
		}
	}

	if re.Action == "notify" || re.Action == "intercept_and_notify" {
		if !s.cfg.NotifyEnabled {
			s.logger.Debug("commsguard: notify disabled by config",
				zap.String("event_id", re.EventID),
			)
			return
		}
		if err := notifier.Notify(ctx, event, notifyMsg); err != nil {
			s.logger.Error("commsguard: notify failed",
				zap.String("channel", re.Channel),
				zap.String("event_id", re.EventID),
				zap.Error(err),
			)
		}
	}
}
