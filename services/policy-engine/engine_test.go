package policyengine

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(Config{PolicyDir: "../../policies"}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestEngine_EvaluateAllow(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	// "read" matches B-ALLOW-003 (read-only operations are auto-allowed).
	event := map[string]interface{}{"event_id": "e1", "domain": "host"}
	decision := e.Evaluate(ctx, event, "read")

	if decision.Decision != DecisionAllow {
		t.Errorf("expected allow for 'read', got %s (rationale: %s)",
			decision.Decision, decision.Rationale)
	}
}

func TestEngine_EvaluateDeny(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	// "disable_logging" violates constitutional principle C-004 → deny.
	event := map[string]interface{}{"event_id": "e2", "domain": "host"}
	decision := e.Evaluate(ctx, event, "disable_logging")

	if decision.Decision != DecisionDeny {
		t.Errorf("expected deny for disable_logging, got %s", decision.Decision)
	}
}

func TestEngine_EvaluateRequireApproval(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	// "process_terminate" matches B-APPROVE-004 → require_approval.
	event := map[string]interface{}{"event_id": "e3", "domain": "host"}
	decision := e.Evaluate(ctx, event, "process_terminate")

	if decision.Decision != DecisionRequireApproval {
		t.Errorf("expected require_approval for process_terminate, got %s (rationale: %s)",
			decision.Decision, decision.Rationale)
	}
}

func TestEngine_DefaultDeny(t *testing.T) {
	e := newTestEngine(t)
	ctx := context.Background()

	// An unknown action hits the fail-safe deny default (C-007).
	event := map[string]interface{}{"event_id": "e4", "domain": "host"}
	decision := e.Evaluate(ctx, event, "completely_unknown_action_xyz")

	if decision.Decision != DecisionDeny {
		t.Errorf("expected deny for unknown action, got %s", decision.Decision)
	}
}
