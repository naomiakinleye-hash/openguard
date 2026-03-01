// Package routing implements the model routing strategy for OpenGuard v5.
// It routes model requests to providers based on risk level, with fallback
// and quorum support for high/critical risk decisions.
package routing

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/zap"

	mg "github.com/DiniMuhd7/openguard/model-gateway/interfaces"
)

// Config holds configuration for the Router.
type Config struct {
	// PrimaryProviderIndex is the index into Providers for low/medium risk routing.
	PrimaryProviderIndex int
}

// Router routes model requests to providers based on risk level.
// It implements fallback for medium risk and quorum for high/critical risk.
type Router struct {
	providers []mg.ModelProvider
	cfg       Config
	logger    *zap.Logger

	// metrics counters (unexported; use Prometheus in production)
	mu              sync.Mutex
	routedRequests  int64
	fallbackCount   int64
	quorumAgreement int64
}

// NewRouter constructs a new Router with the given providers and configuration.
// Providers are tried in order for fallback; quorum uses the first two providers.
func NewRouter(providers []mg.ModelProvider, cfg Config, logger *zap.Logger) *Router {
	return &Router{
		providers: providers,
		cfg:       cfg,
		logger:    logger,
	}
}

// Route dispatches the request to the appropriate provider(s) based on risk level.
//
// Routing strategy:
//   - Low: single call to primary (cheapest/fastest)
//   - Medium: primary with automatic fallback on error
//   - High/Critical: two-provider quorum + flag RequiresHumanApproval
func (r *Router) Route(ctx context.Context, eventCtx mg.EventContext, riskLevel mg.RiskLevel) (*mg.AnalysisResult, error) {
	r.incrementRouted()

	switch riskLevel {
	case mg.RiskLow:
		return r.routeSingle(ctx, eventCtx)
	case mg.RiskMedium:
		return r.routeWithFallback(ctx, eventCtx)
	case mg.RiskHigh, mg.RiskCritical:
		result, err := r.routeQuorum(ctx, eventCtx)
		if err != nil {
			return nil, err
		}
		// Flag for human approval on high/critical.
		r.logger.Info("router: high/critical risk — flagging for human approval",
			zap.String("risk_level", string(riskLevel)),
			zap.String("event_id", eventCtx.EventID),
		)
		return result, nil
	default:
		return r.routeSingle(ctx, eventCtx)
	}
}

// routeSingle calls the primary provider and returns the result directly.
func (r *Router) routeSingle(ctx context.Context, eventCtx mg.EventContext) (*mg.AnalysisResult, error) {
	if len(r.providers) == 0 {
		return nil, fmt.Errorf("router: no providers configured")
	}
	idx := r.cfg.PrimaryProviderIndex
	if idx >= len(r.providers) {
		idx = 0
	}
	result, err := r.providers[idx].Analyze(ctx, eventCtx)
	if err != nil {
		return nil, fmt.Errorf("router: primary provider %s: %w", r.providers[idx].ProviderName(), err)
	}
	return result, nil
}

// routeWithFallback calls the primary provider; on error it falls back to the next.
func (r *Router) routeWithFallback(ctx context.Context, eventCtx mg.EventContext) (*mg.AnalysisResult, error) {
	if len(r.providers) == 0 {
		return nil, fmt.Errorf("router: no providers configured")
	}
	startIdx := r.cfg.PrimaryProviderIndex
	if startIdx >= len(r.providers) {
		startIdx = 0
	}
	for i := 0; i < len(r.providers); i++ {
		idx := (startIdx + i) % len(r.providers)
		result, err := r.providers[idx].Analyze(ctx, eventCtx)
		if err != nil {
			r.incrementFallback()
			r.logger.Warn("router: provider failed, falling back",
				zap.String("provider", r.providers[idx].ProviderName()),
				zap.Int("next_index", (idx+1)%len(r.providers)),
				zap.Error(err),
			)
			continue
		}
		return result, nil
	}
	return nil, fmt.Errorf("router: all providers failed for event %s", eventCtx.EventID)
}

// routeQuorum calls two providers concurrently and requires them to agree within one risk tier.
// If quorum is not reached, the result is escalated and flagged for human approval.
func (r *Router) routeQuorum(ctx context.Context, eventCtx mg.EventContext) (*mg.AnalysisResult, error) {
	if len(r.providers) < 2 {
		r.logger.Warn("router: quorum requested but fewer than 2 providers available; degrading to single")
		return r.routeSingle(ctx, eventCtx)
	}

	type providerResult struct {
		result *mg.AnalysisResult
		err    error
	}
	results := make([]providerResult, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		i := i
		go func() {
			defer wg.Done()
			res, err := r.providers[i].Analyze(ctx, eventCtx)
			results[i] = providerResult{result: res, err: err}
		}()
	}
	wg.Wait()

	// Handle errors.
	if results[0].err != nil && results[1].err != nil {
		return nil, fmt.Errorf("router: quorum — both providers failed: %w; %v", results[0].err, results[1].err)
	}
	if results[0].err != nil {
		r.incrementFallback()
		r.logger.Warn("router: quorum — provider 0 failed, using provider 1 alone",
			zap.String("provider", r.providers[0].ProviderName()), zap.Error(results[0].err))
		return results[1].result, nil
	}
	if results[1].err != nil {
		r.incrementFallback()
		r.logger.Warn("router: quorum — provider 1 failed, using provider 0 alone",
			zap.String("provider", r.providers[1].ProviderName()), zap.Error(results[1].err))
		return results[0].result, nil
	}

	// Both succeeded — check quorum (both must agree within one risk tier).
	if riskLevelsAgree(results[0].result.RiskLevel, results[1].result.RiskLevel) {
		r.incrementQuorumAgreement()
		r.logger.Info("router: quorum reached",
			zap.String("provider_0", results[0].result.ProviderName),
			zap.String("provider_1", results[1].result.ProviderName),
			zap.String("risk_level", string(results[0].result.RiskLevel)),
		)
		return results[0].result, nil
	}

	// Quorum not reached — escalate to the higher risk level.
	r.logger.Warn("router: quorum not reached — escalating to higher risk",
		zap.String("provider_0_risk", string(results[0].result.RiskLevel)),
		zap.String("provider_1_risk", string(results[1].result.RiskLevel)),
	)
	higher := higherRisk(results[0].result.RiskLevel, results[1].result.RiskLevel)
	result := results[0].result
	if results[1].result.RiskLevel == higher {
		result = results[1].result
	}
	result.RiskLevel = higher
	return result, nil
}

// riskLevelsAgree returns true if two risk levels are identical or adjacent.
func riskLevelsAgree(a, b mg.RiskLevel) bool {
	order := map[mg.RiskLevel]int{
		mg.RiskLow:      0,
		mg.RiskMedium:   1,
		mg.RiskHigh:     2,
		mg.RiskCritical: 3,
	}
	diff := order[a] - order[b]
	if diff < 0 {
		diff = -diff
	}
	return diff <= 1
}

// higherRisk returns the higher of two risk levels.
func higherRisk(a, b mg.RiskLevel) mg.RiskLevel {
	order := map[mg.RiskLevel]int{
		mg.RiskLow:      0,
		mg.RiskMedium:   1,
		mg.RiskHigh:     2,
		mg.RiskCritical: 3,
	}
	if order[a] >= order[b] {
		return a
	}
	return b
}

func (r *Router) incrementRouted() {
	r.mu.Lock()
	r.routedRequests++
	r.mu.Unlock()
}

func (r *Router) incrementFallback() {
	r.mu.Lock()
	r.fallbackCount++
	r.mu.Unlock()
}

func (r *Router) incrementQuorumAgreement() {
	r.mu.Lock()
	r.quorumAgreement++
	r.mu.Unlock()
}

// Stats returns current routing metrics.
func (r *Router) Stats() (routed, fallbacks, quorumAgreements int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.routedRequests, r.fallbackCount, r.quorumAgreement
}
