// Package integration contains integration test stubs for OpenGuard v5.
// These tests verify end-to-end event flows with real (but local) service
// instances and mock model providers.
package integration_test

import (
	"context"
	"testing"

	"go.uber.org/zap"

	auditled "github.com/DiniMuhd7/openguard/services/audit-ledger"
	"github.com/DiniMuhd7/openguard/services/detect"
	"github.com/DiniMuhd7/openguard/services/ingest"
	policyengine "github.com/DiniMuhd7/openguard/services/policy-engine"
	orchestrator "github.com/DiniMuhd7/openguard/services/response-orchestrator"
)

// mockEventHandler is a no-op handler used in integration tests.
type mockEventHandler struct {
	events []map[string]interface{}
}

func (m *mockEventHandler) HandleEvent(_ context.Context, event map[string]interface{}) error {
	m.events = append(m.events, event)
	return nil
}

// TestEndToEndEventFlow exercises the full ingest → detect → policy → orchestrator → audit pipeline.
func TestEndToEndEventFlow(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Wire up services.
	ledger := auditled.NewLedger(auditled.Config{}, logger)
	pe, err := policyengine.NewEngine(policyengine.Config{PolicyDir: "../../policies"}, logger)
	if err != nil {
		t.Fatalf("policy engine init: %v", err)
	}
	detectSvc := detect.NewService(detect.Config{RulesDir: "../../rules"}, logger)
	orch := orchestrator.NewOrchestrator(orchestrator.Config{}, pe, ledger, logger)
	handler := &mockEventHandler{}
	svc, err := ingest.NewService(ingest.Config{SchemaPath: "../../schemas/unified-event.schema.json"}, handler, orch, logger)
	if err != nil {
		t.Fatalf("ingest service init: %v", err)
	}

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("ingest service start: %v", err)
	}
	defer svc.Stop()

	// Ingest a minimal valid event.
	rawEvent := []byte(`{
		"event_id": "integ-001",
		"timestamp": "2025-01-01T00:00:00Z",
		"source": {"type": "host", "adapter": "host-agent"},
		"domain": "host",
		"severity": "info",
		"risk_score": 10,
		"tier": "T0",
		"actor": {"id": "proc-1", "type": "process"},
		"target": {"id": "host-1", "type": "host"},
		"indicators": [],
		"policy_citations": [],
		"human_approved": false,
		"audit_hash": "abc123"
	}`)

	if err := svc.Ingest(ctx, rawEvent); err != nil {
		t.Fatalf("ingest failed: %v", err)
	}

	// Verify the event reached the handler.
	if len(handler.events) != 1 {
		t.Errorf("expected 1 event in handler, got %d", len(handler.events))
	}

	// Exercise detection directly.
	event := map[string]interface{}{
		"event_id": "integ-001",
		"domain":   "host",
	}
	result, err := detectSvc.Detect(ctx, event)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if result.Tier == "" {
		t.Error("expected non-empty tier from detect")
	}
}

// TestHumanApprovalWorkflow verifies the approval/denial flow in the orchestrator.
func TestHumanApprovalWorkflow(t *testing.T) {
	logger := zap.NewNop()
	ledger := auditled.NewLedger(auditled.Config{}, logger)
	pe, err := policyengine.NewEngine(policyengine.Config{PolicyDir: "../../policies"}, logger)
	if err != nil {
		t.Fatalf("policy engine init: %v", err)
	}
	orch := orchestrator.NewOrchestrator(orchestrator.Config{}, pe, ledger, logger)

	// Deny should return error for non-existent incident.
	if err := orch.Deny("nonexistent"); err == nil {
		t.Error("expected error for Deny on non-existent incident")
	}
	// Approve should return error for non-existent incident.
	if err := orch.Approve("nonexistent"); err == nil {
		t.Error("expected error for Approve on non-existent incident")
	}
}

// TestModelGatewayRoutingWithMockProviders verifies router routing with mock providers.
func TestModelGatewayRoutingWithMockProviders(t *testing.T) {
	// Stub: real integration test would inject mock providers into the router.
	t.Log("model gateway routing integration test stub — mock providers not yet wired")
}

// TestFallbackOnProviderFailure verifies that the router falls back on provider errors.
func TestFallbackOnProviderFailure(t *testing.T) {
	// Stub: real integration test would inject a failing primary + healthy fallback.
	t.Log("provider fallback integration test stub")
}
