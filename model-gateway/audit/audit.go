// Package audit implements the per-call model audit ledger for the OpenGuard
// model gateway. Every model call produces an immutable audit record that is
// appended to an NDJSON file and published to a NATS topic.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"go.uber.org/zap"
)

const (
	// DefaultStoragePath is the default path for the NDJSON audit log.
	DefaultStoragePath = "audit/model-gateway-audit.ndjson"
	// DefaultNATSTopic is the default NATS topic for audit records.
	DefaultNATSTopic = "openguard.modelguard.audit"
)

// Config holds configuration for AuditLedger.
type Config struct {
	// StoragePath is the file path for the append-only NDJSON audit log.
	// Defaults to DefaultStoragePath. Set to empty string to disable file persistence.
	StoragePath string
	// NATSTopic is the NATS subject to publish audit records to.
	// Defaults to DefaultNATSTopic.
	NATSTopic string
}

// AuditEntry is an immutable record of a single model call.
type AuditEntry struct {
	// CallID is a UUID that uniquely identifies this model call.
	CallID string `json:"call_id"`
	// Timestamp is the RFC3339 time at which the record was created.
	Timestamp string `json:"timestamp"`
	// AgentID identifies the agent that initiated the model call.
	AgentID string `json:"agent_id"`
	// Provider is the model provider name (e.g. "codex", "claude", "gemini").
	Provider string `json:"provider"`
	// InputHash is the SHA-256 hex digest of the sanitized prompt.
	InputHash string `json:"input_hash"`
	// OutputHash is the SHA-256 hex digest of the model response.
	OutputHash string `json:"output_hash"`
	// LatencyMS is the time in milliseconds from dispatch to response.
	LatencyMS int64 `json:"latency_ms"`
	// TokenCount is the total number of tokens (input + output) used, if known.
	TokenCount int `json:"token_count"`
	// RiskLevel is the assessed risk level ("low", "medium", "high", "critical").
	RiskLevel string `json:"risk_level"`
	// RoutingStrategy is the routing strategy used ("single", "fallback", "quorum").
	RoutingStrategy string `json:"routing_strategy"`
	// AuditHash is the SHA-256 of the entire record for tamper-evidence.
	AuditHash string `json:"audit_hash"`
}

// AuditLedger appends model call audit records to an NDJSON file and
// publishes each record to a NATS topic.
type AuditLedger struct {
	cfg    Config
	nc     *nats.Conn // may be nil if NATS is unavailable
	logger *zap.Logger
	mu     sync.Mutex
	file   *os.File
}

// New constructs a new AuditLedger. nc may be nil (NATS publishing is skipped).
func New(cfg Config, nc *nats.Conn, logger *zap.Logger) *AuditLedger {
	if cfg.StoragePath == "" {
		cfg.StoragePath = DefaultStoragePath
	}
	if cfg.NATSTopic == "" {
		cfg.NATSTopic = DefaultNATSTopic
	}
	return &AuditLedger{cfg: cfg, nc: nc, logger: logger}
}

// Open opens (or creates) the backing NDJSON storage file.
// Must be called before Record when StoragePath is set.
func (l *AuditLedger) Open() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cfg.StoragePath == "" {
		return nil // in-memory / NATS-only mode
	}
	f, err := os.OpenFile(l.cfg.StoragePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open file %q: %w", l.cfg.StoragePath, err)
	}
	l.file = f
	return nil
}

// Close flushes and closes the backing storage file.
func (l *AuditLedger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Record appends an audit entry to the ledger. It assigns CallID, Timestamp,
// and AuditHash automatically, then writes to the NDJSON file (if open) and
// publishes to NATS (if connected).
func (l *AuditLedger) Record(_ context.Context, entry AuditEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.CallID = uuid.New().String()
	entry.Timestamp = time.Now().UTC().Format(time.RFC3339)

	auditHash, err := computeAuditHash(entry)
	if err != nil {
		return fmt.Errorf("audit: compute hash: %w", err)
	}
	entry.AuditHash = auditHash

	l.logger.Info("model-gateway audit",
		zap.String("call_id", entry.CallID),
		zap.String("agent_id", entry.AgentID),
		zap.String("provider", entry.Provider),
		zap.Int64("latency_ms", entry.LatencyMS),
		zap.String("risk_level", entry.RiskLevel),
		zap.String("routing_strategy", entry.RoutingStrategy),
		zap.String("audit_hash", entry.AuditHash),
	)

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("audit: marshal entry: %w", err)
	}

	if l.file != nil {
		line = append(line, '\n')
		if _, err := l.file.Write(line); err != nil {
			return fmt.Errorf("audit: write entry: %w", err)
		}
	}

	if l.nc != nil {
		if err := l.nc.Publish(l.cfg.NATSTopic, line); err != nil {
			l.logger.Warn("audit: NATS publish failed",
				zap.String("topic", l.cfg.NATSTopic), zap.Error(err))
		}
	}

	return nil
}

// HashString returns the SHA-256 hex digest of s.
// Callers use this to compute InputHash and OutputHash.
func HashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}

// computeAuditHash returns the SHA-256 of the entry with AuditHash cleared,
// following the same tamper-evidence pattern as services/audit-ledger.
func computeAuditHash(entry AuditEntry) (string, error) {
	entry.AuditHash = ""
	data, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum), nil
}
