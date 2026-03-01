// Package simulation contains simulation test stubs for OpenGuard v5.
// These tests model adversarial scenarios: T3 containment, T4 lockdown,
// false positive measurement, and multi-model quorum.
package simulation_test

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	mg "github.com/DiniMuhd7/openguard/model-gateway/interfaces"
	"github.com/DiniMuhd7/openguard/model-gateway/routing"
	auditled "github.com/DiniMuhd7/openguard/services/audit-ledger"
	"github.com/DiniMuhd7/openguard/services/detect"
	policyengine "github.com/DiniMuhd7/openguard/services/policy-engine"
	orchestrator "github.com/DiniMuhd7/openguard/services/response-orchestrator"
)

// mockProvider is a test-only ModelProvider that returns preset results.
type mockProvider struct {
	name      string
	riskLevel mg.RiskLevel
	failAfter int
	callCount int
}

func (m *mockProvider) ProviderName() string { return m.name }
func (m *mockProvider) HealthCheck(_ context.Context) error { return nil }
func (m *mockProvider) Analyze(_ context.Context, _ mg.EventContext) (*mg.AnalysisResult, error) {
	m.callCount++
	return &mg.AnalysisResult{
		ProviderName: m.name,
		Summary:      "mock analysis",
		Confidence:   0.9,
		RiskLevel:    m.riskLevel,
	}, nil
}
func (m *mockProvider) Classify(_ context.Context, _ mg.RiskContext) (*mg.ClassificationResult, error) {
	return &mg.ClassificationResult{
		ProviderName: m.name,
		RiskLevel:    m.riskLevel,
		RiskScore:    75,
		Confidence:   0.9,
		Rationale:    "mock classification",
	}, nil
}
func (m *mockProvider) ProposeActions(_ context.Context, _ mg.IncidentContext) (*mg.ActionProposal, error) {
	return &mg.ActionProposal{
		ProviderName:          m.name,
		Actions:               []mg.ProposedAction{},
		BlastRadius:           "limited",
		RollbackPlan:          "restore from snapshot",
		RequiresHumanApproval: true,
	}, nil
}
func (m *mockProvider) Explain(_ context.Context, _ mg.DecisionContext) (*mg.Explanation, error) {
	return &mg.Explanation{
		ProviderName:    m.name,
		DecisionID:      "sim-001",
		EvidenceSummary: "mock explanation",
		ConfidenceScore: 0.9,
	}, nil
}

// TestT3ContainmentScenario simulates a T3 high-risk event flowing through the pipeline.
func TestT3ContainmentScenario(t *testing.T) {
	logger := zap.NewNop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ledger := auditled.NewLedger(auditled.Config{}, logger)
	pe, err := policyengine.NewEngine(policyengine.Config{PolicyDir: "../../policies"}, logger)
	if err != nil {
		t.Fatalf("policy engine init: %v", err)
	}
	orch := orchestrator.NewOrchestrator(orchestrator.Config{ApprovalTimeout: 1 * time.Second}, pe, ledger, logger)
	detectSvc := detect.NewService(detect.Config{}, logger)

	// Simulate a high-risk host event.
	event := map[string]interface{}{
		"event_id": "sim-t3-001",
		"domain":   "host",
		"metadata": map[string]interface{}{
			"asset_criticality": "critical",
		},
	}

	result, err := detectSvc.Detect(ctx, event)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	t.Logf("T3 scenario: risk_score=%.2f tier=%s", result.RiskScore, result.Tier)
	event["tier"] = result.Tier
	event["risk_score"] = result.RiskScore

	// Dispatch — will be evaluated by the policy engine; denied actions return immediately.
	_ = orch.Dispatch(ctx, event, "isolate_process")
}

// TestT4EmergencyLockdownScenario simulates a T4 critical event.
func TestT4EmergencyLockdownScenario(t *testing.T) {
	logger := zap.NewNop()
	// Use a short approval timeout so the test completes quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ledger := auditled.NewLedger(auditled.Config{}, logger)
	pe, err := policyengine.NewEngine(policyengine.Config{PolicyDir: "../../policies"}, logger)
	if err != nil {
		t.Fatalf("policy engine init: %v", err)
	}
	orch := orchestrator.NewOrchestrator(orchestrator.Config{ApprovalTimeout: 1 * time.Second}, pe, ledger, logger)

	event := map[string]interface{}{
		"event_id":   "sim-t4-001",
		"domain":     "host",
		"tier":       "T4",
		"risk_score": 95.0,
	}

	// T4 dispatch may require approval and escalate — accept both outcomes.
	err = orch.Dispatch(ctx, event, "emergency_lockdown")
	if err != nil {
		t.Logf("T4 scenario dispatch returned: %v (may be expected for approval/timeout path)", err)
	} else {
		t.Log("T4 scenario: dispatch completed")
	}
}

// TestFalsePositiveRateMeasurementScaffold measures false positive rate against a
// corpus of known-good events.
func TestFalsePositiveRateMeasurementScaffold(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()
	detectSvc := detect.NewService(detect.Config{}, logger)

	// Known-good events that should score T0 or T1 (non-critical).
	knownGoodEvents := []map[string]interface{}{
		{"event_id": "fp-001", "domain": "comms", "metadata": map[string]interface{}{"asset_criticality": "low"}},
		{"event_id": "fp-002", "domain": "comms"},
		{"event_id": "fp-003", "domain": "host"},
	}

	falsePositives := 0
	for _, event := range knownGoodEvents {
		result, err := detectSvc.Detect(ctx, event)
		if err != nil {
			t.Logf("detect error for %s: %v", event["event_id"], err)
			continue
		}
		if result.Tier == "T3" || result.Tier == "T4" {
			falsePositives++
			t.Logf("false positive: event %s scored %s (risk=%.2f)", event["event_id"], result.Tier, result.RiskScore)
		}
	}

	fpRate := float64(falsePositives) / float64(len(knownGoodEvents))
	t.Logf("false positive rate: %.2f%% (%d/%d)", fpRate*100, falsePositives, len(knownGoodEvents))

	// Threshold: less than 5% false positive rate on known-good corpus.
	if fpRate > 0.05 {
		t.Errorf("false positive rate %.2f%% exceeds 5%% threshold", fpRate*100)
	}
}

// TestMultiModelQuorumScenario exercises the router quorum logic with mock providers.
func TestMultiModelQuorumScenario(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Two providers that agree.
	p1 := &mockProvider{name: "mock-codex", riskLevel: mg.RiskHigh}
	p2 := &mockProvider{name: "mock-claude", riskLevel: mg.RiskHigh}
	router := routing.NewRouter([]mg.ModelProvider{p1, p2}, routing.Config{}, logger)

	eventCtx := mg.EventContext{
		EventID:    "quorum-001",
		Domain:     "host",
		RawPayload: "suspicious process spawned",
		Timestamp:  time.Now(),
	}
	result, err := router.Route(ctx, eventCtx, mg.RiskHigh)
	if err != nil {
		t.Fatalf("quorum route failed: %v", err)
	}
	if result.RiskLevel != mg.RiskHigh {
		t.Errorf("expected quorum risk level high, got %s", result.RiskLevel)
	}

	routed, fallbacks, agreements := router.Stats()
	t.Logf("router stats: routed=%d fallbacks=%d quorum_agreements=%d", routed, fallbacks, agreements)
	if agreements != 1 {
		t.Errorf("expected 1 quorum agreement, got %d", agreements)
	}
}
