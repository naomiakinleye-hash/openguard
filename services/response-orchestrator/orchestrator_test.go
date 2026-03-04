package orchestrator

import (
	"context"
	"testing"
	"time"

	"go.uber.org/zap"

	auditled "github.com/DiniMuhd7/openguard/services/audit-ledger"
	policyengine "github.com/DiniMuhd7/openguard/services/policy-engine"
)

func newTestOrchestrator(t *testing.T, sink IncidentSink) *Orchestrator {
	t.Helper()
	ledger := auditled.NewLedger(auditled.Config{}, zap.NewNop())
	pe, err := policyengine.NewEngine(policyengine.Config{PolicyDir: "../../policies"}, zap.NewNop())
	if err != nil {
		t.Fatalf("policy engine init: %v", err)
	}
	return NewOrchestrator(Config{
		ApprovalTimeout: 100 * time.Millisecond,
		IncidentSink:    sink,
	}, pe, ledger, zap.NewNop())
}

// mockIncidentSink records incidents added.
type mockIncidentSink struct {
	incidents []*OrchestratorIncident
}

func (m *mockIncidentSink) Add(inc *OrchestratorIncident) {
	m.incidents = append(m.incidents, inc)
}

func TestOrchestrator_Dispatch_T0(t *testing.T) {
	orch := newTestOrchestrator(t, nil)
	ctx := context.Background()

	// T0 event with an allowed action should be auto-resolved (log only).
	event := map[string]interface{}{
		"event_id": "e-t0",
		"tier":     "T0",
		"domain":   "host",
	}
	if err := orch.Dispatch(ctx, event, "read"); err != nil {
		t.Fatalf("Dispatch T0 failed: %v", err)
	}
}

func TestOrchestrator_Dispatch_RequiresApproval(t *testing.T) {
	sink := &mockIncidentSink{}
	orch := newTestOrchestrator(t, sink)
	ctx := context.Background()

	// T2 event should enter pending approval; with short timeout it escalates.
	event := map[string]interface{}{
		"event_id": "e-t2",
		"tier":     "T2",
		"domain":   "host",
	}
	// Use a background context that we cancel quickly to avoid long waits.
	ctx2, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()

	// Dispatch will request approval and time out / or complete via context.
	_ = orch.Dispatch(ctx2, event, "read")

	// If the sink was set, it should have received the incident.
	if len(sink.incidents) == 0 {
		t.Error("expected incident sink to receive at least one incident")
	}
	if sink.incidents[0].Status != "pending" {
		t.Errorf("expected incident status=pending, got %s", sink.incidents[0].Status)
	}
}

func TestOrchestrator_Approve(t *testing.T) {
	orch := newTestOrchestrator(t, nil)

	// Approve on non-existent incident must return error.
	if err := orch.Approve("nonexistent"); err == nil {
		t.Error("expected error for Approve on non-existent incident")
	}

	// Deny on non-existent incident must return error.
	if err := orch.Deny("nonexistent"); err == nil {
		t.Error("expected error for Deny on non-existent incident")
	}
}
