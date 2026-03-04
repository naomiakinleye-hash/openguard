package detect

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func TestService_HandleEvent_TierAssignment(t *testing.T) {
	tests := []struct {
		name      string
		riskScore float64
		wantTier  string
	}{
		{"T0 lower bound", 0, "T0"},
		{"T0 upper bound", 19, "T0"},
		{"T1 lower bound", 20, "T1"},
		{"T1 upper bound", 39, "T1"},
		{"T2 lower bound", 40, "T2"},
		{"T2 upper bound", 59, "T2"},
		{"T3 lower bound", 60, "T3"},
		{"T3 upper bound", 79, "T3"},
		{"T4 lower bound", 80, "T4"},
		{"T4 upper bound", 100, "T4"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := assignTier(tc.riskScore)
			if got != tc.wantTier {
				t.Errorf("assignTier(%.0f) = %s, want %s", tc.riskScore, got, tc.wantTier)
			}
		})
	}
}

// mockSink records calls to Add.
type mockSink struct {
	calls []map[string]interface{}
}

func (m *mockSink) Add(event map[string]interface{}) {
	m.calls = append(m.calls, event)
}

func TestService_HandleEvent_SinkCalled(t *testing.T) {
	sink := &mockSink{}
	svc := NewService(Config{Sink: sink}, zap.NewNop())
	ctx := context.Background()

	event := map[string]interface{}{
		"event_id": "evt-sink-test",
		"domain":   "host",
	}
	if err := svc.HandleEvent(ctx, event); err != nil {
		t.Fatalf("HandleEvent failed: %v", err)
	}

	if len(sink.calls) != 1 {
		t.Fatalf("expected 1 sink call, got %d", len(sink.calls))
	}
	// The enriched event should have risk_score and tier fields.
	if _, ok := sink.calls[0]["risk_score"]; !ok {
		t.Error("expected risk_score in sink event")
	}
	if _, ok := sink.calls[0]["tier"]; !ok {
		t.Error("expected tier in sink event")
	}
}

func TestService_HandleEvent_NoSink(t *testing.T) {
	svc := NewService(Config{}, zap.NewNop())
	ctx := context.Background()

	event := map[string]interface{}{
		"event_id": "evt-no-sink",
		"domain":   "agent",
	}
	if err := svc.HandleEvent(ctx, event); err != nil {
		t.Fatalf("HandleEvent failed: %v", err)
	}
	// No panic; event should be enriched in place.
	if event["tier"] == "" {
		t.Error("expected tier to be set")
	}
}
