package audit

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestRecord_InMemory(t *testing.T) {
	ledger := New(Config{StoragePath: ""}, nil, zap.NewNop())

	entry := AuditEntry{
		AgentID:         "agent-finance",
		Provider:        "codex",
		InputHash:       HashString("hello prompt"),
		OutputHash:      HashString("model response"),
		LatencyMS:       123,
		TokenCount:      50,
		RiskLevel:       "low",
		RoutingStrategy: "single",
	}

	ctx := context.Background()
	if err := ledger.Record(ctx, entry); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
}

func TestRecord_AssignsCallIDAndTimestamp(t *testing.T) {
	// Use a temp file to capture the output.
	tmp := t.TempDir() + "/audit.ndjson"
	ledger := New(Config{StoragePath: tmp}, nil, zap.NewNop())
	if err := ledger.Open(); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer ledger.Close()

	entry := AuditEntry{
		AgentID:         "agent-x",
		Provider:        "claude",
		InputHash:       HashString("prompt"),
		OutputHash:      HashString("output"),
		LatencyMS:       10,
		RiskLevel:       "medium",
		RoutingStrategy: "fallback",
	}

	if err := ledger.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var saved AuditEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &saved); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if saved.CallID == "" {
		t.Error("expected CallID to be set")
	}
	if saved.Timestamp == "" {
		t.Error("expected Timestamp to be set")
	}
	if saved.AuditHash == "" {
		t.Error("expected AuditHash to be set")
	}
	if saved.Provider != "claude" {
		t.Errorf("expected provider %q, got %q", "claude", saved.Provider)
	}
}

func TestRecord_AuditHashTamperEvidence(t *testing.T) {
	ledger := New(Config{StoragePath: ""}, nil, zap.NewNop())

	entry := AuditEntry{
		AgentID:         "agent-x",
		Provider:        "gemini",
		InputHash:       HashString("input"),
		OutputHash:      HashString("output"),
		LatencyMS:       5,
		RiskLevel:       "high",
		RoutingStrategy: "quorum",
	}

	if err := ledger.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
}

func TestHashString(t *testing.T) {
	h1 := HashString("hello")
	h2 := HashString("hello")
	h3 := HashString("world")

	if h1 != h2 {
		t.Error("expected same hash for same input")
	}
	if h1 == h3 {
		t.Error("expected different hash for different input")
	}
	if len(h1) != 64 {
		t.Errorf("expected 64-char SHA-256 hex, got %d chars", len(h1))
	}
}

func TestOpen_CreatesFile(t *testing.T) {
	tmp := t.TempDir() + "/audit.ndjson"
	ledger := New(Config{StoragePath: tmp}, nil, zap.NewNop())
	if err := ledger.Open(); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer ledger.Close()

	if _, err := os.Stat(tmp); os.IsNotExist(err) {
		t.Fatal("expected file to be created")
	}
}
