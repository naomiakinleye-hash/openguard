// Package networkguard provides the NetworkGuard sensor — a network intelligence
// layer that subscribes to HostGuard raw events, filters for network-related
// event types, enriches them with AI-powered threat classification via the
// model-gateway, and republishes as network-domain events.
package networkguard

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	common "github.com/DiniMuhd7/openguard/adapters/networkguard/common"
	"github.com/google/uuid"
	nats "github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

// NetworkGuardSensor subscribes to openguard.hostguard.raw, filters for
// network event types, enriches with AI, and re-publishes to
// openguard.networkguard.raw with domain="network".
type NetworkGuardSensor struct {
	cfg         common.Config
	nc          *nats.Conn // shared NATS conn for subscribe + publish
	modelNC     *nats.Conn // dedicated NATS conn for AI enrichment
	modelClient *common.NetworkModelIntelClient
	logger      *zap.Logger
	sub         *nats.Subscription
	wg          sync.WaitGroup
	mu          sync.Mutex
	running     bool
	cancelFn    context.CancelFunc
}

// NewNetworkGuardSensor creates a NetworkGuardSensor.
func NewNetworkGuardSensor(cfg common.Config, logger *zap.Logger) (*NetworkGuardSensor, error) {
	if cfg.NATSUrl == "" {
		cfg.NATSUrl = "nats://localhost:4222"
	}
	if cfg.SourceTopic == "" {
		cfg.SourceTopic = "openguard.hostguard.raw"
	}
	if cfg.PublishTopic == "" {
		cfg.PublishTopic = "openguard.networkguard.raw"
	}

	nc, err := nats.Connect(cfg.NATSUrl,
		nats.Name("openguard-networkguard"),
		nats.MaxReconnects(-1),
	)
	if err != nil {
		return nil, fmt.Errorf("networkguard: connect to NATS: %w", err)
	}

	s := &NetworkGuardSensor{
		cfg:    cfg,
		nc:     nc,
		logger: logger,
	}

	// Wire AI enrichment when enabled.
	if cfg.ModelGatewayEnabled {
		modelNC, ncErr := nats.Connect(cfg.NATSUrl,
			nats.Name("openguard-networkguard-ai"),
			nats.MaxReconnects(-1),
		)
		if ncErr != nil {
			logger.Warn("networkguard: AI enrichment NATS connect failed — running without AI",
				zap.Error(ncErr))
		} else {
			s.modelNC = modelNC
			s.modelClient = common.NewNetworkModelIntelClient(
				modelNC,
				cfg.ModelGatewayTopic,
				cfg.ModelGatewayTimeout,
				cfg.ModelGatewayAgentID,
				logger,
			)
			logger.Info("networkguard: AI enrichment enabled",
				zap.String("topic", cfg.ModelGatewayTopic),
				zap.String("agent_id", cfg.ModelGatewayAgentID),
			)
		}
	}

	return s, nil
}

// Start begins subscribing to HostGuard events and processing them.
func (s *NetworkGuardSensor) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	innerCtx, cancel := context.WithCancel(ctx)
	s.cancelFn = cancel

	sub, err := s.nc.Subscribe(s.cfg.SourceTopic, func(msg *nats.Msg) {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.processEvent(innerCtx, msg.Data)
		}()
	})
	if err != nil {
		cancel()
		return fmt.Errorf("networkguard: subscribe to %s: %w", s.cfg.SourceTopic, err)
	}

	s.sub = sub
	s.running = true
	s.logger.Info("networkguard: sensor started",
		zap.String("source_topic", s.cfg.SourceTopic),
		zap.String("publish_topic", s.cfg.PublishTopic),
	)
	return nil
}

// Stop gracefully shuts down the sensor.
func (s *NetworkGuardSensor) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancelFn != nil {
		s.cancelFn()
	}
	if s.sub != nil {
		s.sub.Unsubscribe() //nolint:errcheck
	}

	s.wg.Wait()
	s.nc.Drain()           //nolint:errcheck
	if s.modelNC != nil {
		s.modelNC.Drain() //nolint:errcheck
	}

	s.running = false
	return nil
}

// HealthCheck returns an error if the sensor is not running.
func (s *NetworkGuardSensor) HealthCheck(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return fmt.Errorf("networkguard: sensor is not running")
	}
	return nil
}

// processEvent parses a HostGuard unified event, filters for network event
// types, enriches with AI, and republishes with domain="network".
func (s *NetworkGuardSensor) processEvent(ctx context.Context, data []byte) {
	var event map[string]interface{}
	if err := json.Unmarshal(data, &event); err != nil {
		s.logger.Debug("networkguard: failed to parse event", zap.Error(err))
		return
	}

	// Only process host-domain events with network-related event types.
	domain, _ := event["domain"].(string)
	if domain != "host" {
		return
	}

	meta, _ := event["metadata"].(map[string]interface{})
	if meta == nil {
		return
	}

	eventType, _ := meta["event_type"].(string)
	if !common.NetworkEventTypes[eventType] {
		return
	}

	// Collect existing indicators from the HostGuard event.
	var existingIndicators []string
	if inds, ok := event["indicators"].([]interface{}); ok {
		for _, i := range inds {
			if s, ok := i.(string); ok {
				existingIndicators = append(existingIndicators, s)
			}
		}
	}

	// Stage: AI enrichment — get novel network-specific indicators.
	var allIndicators []string
	allIndicators = append(allIndicators, existingIndicators...)
	if s.modelClient != nil {
		novel := s.modelClient.Enrich(ctx, event, existingIndicators)
		allIndicators = append(allIndicators, novel...)
	}

	// Build the enriched network-domain event.
	networkEvent := s.buildNetworkEvent(event, allIndicators)
	payload, err := json.Marshal(networkEvent)
	if err != nil {
		s.logger.Warn("networkguard: marshal enriched event failed", zap.Error(err))
		return
	}

	if err := s.nc.Publish(s.cfg.PublishTopic, payload); err != nil {
		s.logger.Warn("networkguard: publish failed",
			zap.String("topic", s.cfg.PublishTopic),
			zap.Error(err),
		)
		return
	}

	s.logger.Debug("networkguard: published network event",
		zap.String("event_type", eventType),
		zap.Strings("indicators", allIndicators),
	)
}

// buildNetworkEvent constructs a new unified event with domain="network" and
// adapter="networkguard" from an incoming HostGuard unified event.
func (s *NetworkGuardSensor) buildNetworkEvent(original map[string]interface{}, indicators []string) map[string]interface{} {
	// Recalculate risk/tier based on network-specific indicators.
	severity, riskScore, tier := classifyNetworkIndicators(indicators)

	// Build the source map — copy host_id from original but override adapter.
	srcMap := map[string]interface{}{
		"type":    "network",
		"adapter": "networkguard",
	}
	if origSrc, ok := original["source"].(map[string]interface{}); ok {
		if hostID, _ := origSrc["host_id"].(string); hostID != "" {
			srcMap["host_id"] = hostID
		}
	}

	// Preserve the original actor/target as-is.
	actor := original["actor"]
	if actor == nil {
		actor = map[string]interface{}{"id": "unknown", "type": "process"}
	}
	target := original["target"]
	if target == nil {
		target = map[string]interface{}{"id": "unknown"}
	}

	if indicators == nil {
		indicators = []string{}
	}

	// Compute a simple audit hash from the new event_id.
	newID := uuid.New().String()
	auditHash := fmt.Sprintf("%x", []byte(newID))

	return map[string]interface{}{
		"event_id":        newID,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"source":          srcMap,
		"domain":          "network",
		"severity":        severity,
		"risk_score":      riskScore,
		"tier":            tier,
		"actor":           actor,
		"target":          target,
		"indicators":      indicators,
		"policy_citations": []string{},
		"human_approved":  false,
		"audit_hash":      auditHash,
		"metadata":        original["metadata"],
	}
}

// classifyNetworkIndicators maps network indicators to severity/risk/tier.
func classifyNetworkIndicators(indicators []string) (severity string, riskScore float64, tier string) {
	criticalSet := map[string]bool{
		"c2_beaconing": true, "domain_generation_algo": true, "encrypted_c2": true,
		"data_exfiltration": true, "low_and_slow_exfiltration": true,
	}
	highSet := map[string]bool{
		"lateral_movement": true, "dns_tunneling": true, "network_reconnaissance": true,
	}
	mediumSet := map[string]bool{
		"port_scan": true, "protocol_anomaly": true, "geo_ip_anomaly": true,
		"remote_access_anomaly": true, "unauthorized_service": true,
		"suspicious_dns_query": true, "connection_flood": true,
	}

	for _, ind := range indicators {
		if criticalSet[ind] {
			return "critical", 90.0, "T4"
		}
	}
	for _, ind := range indicators {
		if highSet[ind] {
			return "high", 70.0, "T3"
		}
	}
	for _, ind := range indicators {
		if mediumSet[ind] {
			return "medium", 50.0, "T2"
		}
	}
	if len(indicators) > 0 {
		return "low", 25.0, "T1"
	}
	return "info", 12.5, "T0"
}
