// Package auditled implements the OpenGuard v5 tamper-evident audit ledger.
// Entries are chained using SHA-256 so any modification of historical records
// is detectable.
package auditled

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Config holds configuration for the Ledger.
type Config struct {
	// StoragePath is the file path for the append-only NDJSON audit log.
	StoragePath string
}

// AuditEntry represents a single immutable audit record.
type AuditEntry struct {
	// ID is a unique identifier for this entry (set by Append).
	ID string `json:"id"`
	// Timestamp is when the entry was appended (set by Append).
	Timestamp time.Time `json:"timestamp"`
	// EventID is the security event this entry relates to.
	EventID string `json:"event_id"`
	// Actor identifies who or what performed the action.
	Actor string `json:"actor"`
	// Action is a description of what was done.
	Action string `json:"action"`
	// Decision is the policy decision outcome.
	Decision string `json:"decision"`
	// PolicyCitations are the policy rule IDs that drove the decision.
	PolicyCitations []string `json:"policy_citations,omitempty"`
	// Hash is the SHA-256 hash of this entry's canonical representation.
	Hash string `json:"hash"`
	// PrevHash is the SHA-256 hash of the previous entry (empty for the first).
	PrevHash string `json:"prev_hash"`
}

// Ledger is the append-only, tamper-evident audit ledger.
type Ledger struct {
	cfg      Config
	logger   *zap.Logger
	mu       sync.Mutex
	prevHash string
	sequence int64
	file     *os.File
	entries  []AuditEntry // in-memory entry cache for querying
}

// NewLedger constructs a new Ledger.
func NewLedger(cfg Config, logger *zap.Logger) *Ledger {
	return &Ledger{cfg: cfg, logger: logger}
}

// Open opens (or creates) the backing storage file.
// It must be called before Append.
func (l *Ledger) Open() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cfg.StoragePath == "" {
		return nil // in-memory mode; entries are logged but not persisted.
	}
	f, err := os.OpenFile(l.cfg.StoragePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit ledger: open file: %w", err)
	}
	l.file = f
	return nil
}

// Close flushes and closes the backing storage file.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Append adds an entry to the ledger.
// It sets ID, Timestamp, Hash, and PrevHash automatically.
func (l *Ledger) Append(_ context.Context, entry AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sequence++
	entry.ID = fmt.Sprintf("audit-%d-%d", time.Now().UnixNano(), l.sequence)
	entry.Timestamp = time.Now().UTC()
	entry.PrevHash = l.prevHash

	hash, err := computeHash(entry)
	if err != nil {
		return fmt.Errorf("audit ledger: compute hash: %w", err)
	}
	entry.Hash = hash
	l.prevHash = hash

	// Cache entry in memory.
	l.entries = append(l.entries, entry)

	l.logger.Info("audit",
		zap.String("id", entry.ID),
		zap.String("event_id", entry.EventID),
		zap.String("actor", entry.Actor),
		zap.String("action", entry.Action),
		zap.String("decision", entry.Decision),
		zap.String("hash", entry.Hash),
		zap.String("prev_hash", entry.PrevHash),
	)

	if l.file != nil {
		line, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("audit ledger: marshal entry: %w", err)
		}
		line = append(line, '\n')
		if _, err := l.file.Write(line); err != nil {
			return fmt.Errorf("audit ledger: write entry: %w", err)
		}
	}
	return nil
}

// GetByEventID returns all audit entries for a given event ID.
func (l *Ledger) GetByEventID(_ context.Context, eventID string) ([]AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var result []AuditEntry
	for _, e := range l.entries {
		if e.EventID == eventID || eventID == "" {
			result = append(result, e)
		}
	}
	return result, nil
}

// GetByTimeRange returns all entries within [start, end].
func (l *Ledger) GetByTimeRange(_ context.Context, start, end time.Time) ([]AuditEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var result []AuditEntry
	for _, e := range l.entries {
		if !e.Timestamp.Before(start) && !e.Timestamp.After(end) {
			result = append(result, e)
		}
	}
	return result, nil
}

// Entries returns a copy of all entries in the ledger (for testing and export).
func (l *Ledger) Entries() []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]AuditEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// computeHash returns the SHA-256 hash of an AuditEntry's canonical JSON
// (with Hash field set to empty string to avoid circular dependency).
func computeHash(entry AuditEntry) (string, error) {
	entry.Hash = ""
	data, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}

// VerifyChain checks tamper-evidence for a slice of entries in order.
// Returns an error if any entry's hash or chain link is invalid.
func VerifyChain(entries []AuditEntry) error {
	var prevHash string
	for i, entry := range entries {
		// Recompute expected hash.
		expected, err := computeHash(entry)
		if err != nil {
			return fmt.Errorf("audit ledger: verify entry %d: compute hash: %w", i, err)
		}
		if entry.Hash != expected {
			return fmt.Errorf("audit ledger: entry %d (%s) hash mismatch: got %s, want %s",
				i, entry.ID, entry.Hash, expected)
		}
		if entry.PrevHash != prevHash {
			return fmt.Errorf("audit ledger: entry %d (%s) prev_hash mismatch", i, entry.ID)
		}
		prevHash = entry.Hash
	}
	return nil
}
