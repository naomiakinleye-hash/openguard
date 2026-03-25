// Package agentguard provides the AgentGuard sensor that intercepts AI agent
// actions, evaluates them against policy, and emits audit events.
package agentguard

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/agentguard/common"
	interceptor "github.com/DiniMuhd7/openguard/adapters/agentguard/interceptor"
	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// AgentGuardSensor wires the registry, publisher, compliance checker,
// and HTTP interceptor into a runnable sensor.
type AgentGuardSensor struct {
	cfg         common.Config
	registry    *common.AgentRegistry
	publisher   *common.Publisher
	checker     *common.PolicyComplianceChecker
	interceptor *interceptor.AgentInterceptor
	logger      *zap.Logger
	modelNC     *nats.Conn // dedicated NATS conn for AI enrichment

	mux    *http.ServeMux
	server *http.Server
	wg     sync.WaitGroup

	mu       sync.Mutex
	running  bool
	cancelFn context.CancelFunc
}

// NewAgentGuardSensor creates a new AgentGuardSensor, connecting to NATS and
// initialising all internal components.
func NewAgentGuardSensor(cfg common.Config, logger *zap.Logger) (*AgentGuardSensor, error) {
	if cfg.NATSUrl == "" {
		cfg.NATSUrl = "nats://localhost:4222"
	}
	if cfg.RawEventTopic == "" {
		cfg.RawEventTopic = "openguard.agentguard.raw"
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8095"
	}

	publisher, err := common.NewPublisher(cfg.NATSUrl, cfg.RawEventTopic, logger)
	if err != nil {
		return nil, fmt.Errorf("agentguard: create publisher: %w", err)
	}

	registry := common.NewAgentRegistry()
	checker := common.NewPolicyComplianceChecker()
	inter := interceptor.NewAgentInterceptor(registry, publisher, checker, logger)

	// Wire AI enrichment when enabled.
	var modelNC *nats.Conn
	if cfg.ModelGatewayEnabled {
		nc, ncErr := nats.Connect(cfg.NATSUrl,
			nats.Name("openguard-agentguard-ai"),
			nats.MaxReconnects(-1),
		)
		if ncErr != nil {
			logger.Warn("agentguard: AI enrichment NATS connect failed — running without AI",
				zap.Error(ncErr))
		} else {
			modelNC = nc
			mc := common.NewAgentModelIntelClient(nc, cfg.ModelGatewayTopic, cfg.ModelGatewayTimeout, cfg.ModelGatewayAgentID, logger)
			inter.WithModelIntelClient(mc)
			logger.Info("agentguard: AI enrichment enabled",
				zap.String("topic", cfg.ModelGatewayTopic),
				zap.String("agent_id", cfg.ModelGatewayAgentID),
			)
		}
	}

	mux := http.NewServeMux()
	inter.RegisterRoutes(mux)

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
	}

	return &AgentGuardSensor{
		cfg:         cfg,
		registry:    registry,
		publisher:   publisher,
		checker:     checker,
		interceptor: inter,
		logger:      logger,
		modelNC:     modelNC,
		mux:         mux,
		server:      server,
	}, nil
}

// Start begins the HTTP server.
func (s *AgentGuardSensor) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	innerCtx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel

	_ = innerCtx // held for future goroutine lifecycle use

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.logger.Info("agentguard: HTTP server listening", zap.String("addr", s.cfg.ListenAddr))
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("agentguard: HTTP server error", zap.Error(err))
		}
	}()

	s.running = true
	return nil
}

// Stop gracefully shuts down the HTTP server and closes the publisher.
func (s *AgentGuardSensor) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancelFn != nil {
		s.cancelFn()
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := s.server.Shutdown(shutdownCtx); err != nil {
		s.logger.Warn("agentguard: HTTP server shutdown error", zap.Error(err))
	}

	s.wg.Wait()
	s.publisher.Close()
	if s.modelNC != nil {
		s.modelNC.Drain() //nolint:errcheck
	}
	s.running = false
	return nil
}

// HealthCheck returns an error if the sensor is not running.
func (s *AgentGuardSensor) HealthCheck(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return fmt.Errorf("agentguard: sensor is not running")
	}
	return nil
}

// Registry returns the AgentRegistry for pre-seeding agents before Start.
func (s *AgentGuardSensor) Registry() *common.AgentRegistry {
	return s.registry
}
