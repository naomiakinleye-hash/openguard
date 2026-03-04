package auditled

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func newTestLedger(t *testing.T) *Ledger {
	t.Helper()
	return NewLedger(Config{}, zap.NewNop())
}

func TestAppend_HashChain(t *testing.T) {
	l := newTestLedger(t)
	ctx := context.Background()

	for i, action := range []string{"login", "query", "logout"} {
		_ = i
		if err := l.Append(ctx, AuditEntry{
			EventID:  "evt-1",
			Actor:    "test",
			Action:   action,
			Decision: "allow",
		}); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	entries := l.Entries()
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}

	// Verify chain integrity.
	if err := VerifyChain(entries); err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}

	// Check linking.
	if entries[1].PrevHash != entries[0].Hash {
		t.Error("entry[1].PrevHash should equal entry[0].Hash")
	}
	if entries[2].PrevHash != entries[1].Hash {
		t.Error("entry[2].PrevHash should equal entry[1].Hash")
	}
}

func TestGetByEventID(t *testing.T) {
	l := newTestLedger(t)
	ctx := context.Background()

	l.Append(ctx, AuditEntry{EventID: "evt-A", Actor: "a", Action: "x", Decision: "allow"})  //nolint:errcheck
	l.Append(ctx, AuditEntry{EventID: "evt-B", Actor: "b", Action: "y", Decision: "allow"})  //nolint:errcheck
	l.Append(ctx, AuditEntry{EventID: "evt-A", Actor: "a", Action: "z", Decision: "deny"})   //nolint:errcheck

	results, err := l.GetByEventID(ctx, "evt-A")
	if err != nil {
		t.Fatalf("GetByEventID failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 entries for evt-A, got %d", len(results))
	}

	// Empty event_id should return all entries.
	all, err := l.GetByEventID(ctx, "")
	if err != nil {
		t.Fatalf("GetByEventID('') failed: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 entries for empty event_id, got %d", len(all))
	}
}

func TestVerifyChain_Tampered(t *testing.T) {
	l := newTestLedger(t)
	ctx := context.Background()

	l.Append(ctx, AuditEntry{EventID: "e1", Actor: "a", Action: "x", Decision: "allow"}) //nolint:errcheck
	l.Append(ctx, AuditEntry{EventID: "e2", Actor: "a", Action: "y", Decision: "allow"}) //nolint:errcheck
	l.Append(ctx, AuditEntry{EventID: "e3", Actor: "a", Action: "z", Decision: "allow"}) //nolint:errcheck

	entries := l.Entries()
	// Tamper with the middle entry's decision.
	entries[1].Decision = "tampered"

	if err := VerifyChain(entries); err == nil {
		t.Fatal("expected VerifyChain to return error for tampered entries")
	}
}

func TestOpen_CreateAndReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.ndjson")

	// First open: creates file.
	l1 := NewLedger(Config{StoragePath: path}, zap.NewNop())
	if err := l1.Open(); err != nil {
		t.Fatalf("Open (create) failed: %v", err)
	}
	ctx := context.Background()
	l1.Append(ctx, AuditEntry{EventID: "e1", Actor: "a", Action: "x", Decision: "allow"}) //nolint:errcheck
	l1.Close()                                                                              //nolint:errcheck

	// File must exist.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected audit file to be created")
	}

	// Reopen and append.
	l2 := NewLedger(Config{StoragePath: path}, zap.NewNop())
	if err := l2.Open(); err != nil {
		t.Fatalf("Open (reopen) failed: %v", err)
	}
	l2.Append(ctx, AuditEntry{EventID: "e2", Actor: "b", Action: "y", Decision: "allow"}) //nolint:errcheck
	l2.Close()                                                                              //nolint:errcheck

	// File should still exist.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected audit file to survive reopen")
	}
}
