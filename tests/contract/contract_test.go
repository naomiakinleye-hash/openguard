// Package contract contains contract tests for OpenGuard v5.
// These tests verify that all providers implement the ModelProvider interface,
// all adapters produce valid UnifiedEvent structs, the policy engine correctly
// blocks prohibited action classes, and the audit ledger is tamper-evident.
package contract_test

import (
"context"
"testing"

mg "github.com/DiniMuhd7/openguard/model-gateway/interfaces"
"github.com/DiniMuhd7/openguard/model-gateway/providers/claude"
"github.com/DiniMuhd7/openguard/model-gateway/providers/codex"
"github.com/DiniMuhd7/openguard/model-gateway/providers/gemini"
auditled "github.com/DiniMuhd7/openguard/services/audit-ledger"
policyengine "github.com/DiniMuhd7/openguard/services/policy-engine"
"go.uber.org/zap"
)

// ---- ModelProvider interface compliance ----

// TestCodexProviderImplementsInterface verifies CodexProvider satisfies ModelProvider.
func TestCodexProviderImplementsInterface(t *testing.T) {
var _ mg.ModelProvider = codex.NewCodexProvider(codex.Config{APIKey: "test"}, zap.NewNop())
}

// TestClaudeProviderImplementsInterface verifies ClaudeProvider satisfies ModelProvider.
func TestClaudeProviderImplementsInterface(t *testing.T) {
var _ mg.ModelProvider = claude.NewClaudeProvider(claude.Config{APIKey: "test"}, zap.NewNop())
}

// TestGeminiProviderImplementsInterface verifies GeminiProvider satisfies ModelProvider.
func TestGeminiProviderImplementsInterface(t *testing.T) {
var _ mg.ModelProvider = gemini.NewGeminiProvider(gemini.Config{APIKey: "test"}, zap.NewNop())
}

// ---- Policy engine: prohibited action blocking ----

// TestPolicyEngineBlocksDisableLogging verifies that disabling logging is always blocked.
func TestPolicyEngineBlocksDisableLogging(t *testing.T) {
logger := zap.NewNop()
engine, err := policyengine.NewEngine(policyengine.Config{PolicyDir: "../../policies"}, logger)
if err != nil {
t.Fatalf("failed to create policy engine: %v", err)
}
ctx := context.Background()
event := map[string]interface{}{
"event_id": "test-001",
"domain":   "host",
}
decision := engine.Evaluate(ctx, event, "disable_logging")
if decision.Decision != policyengine.DecisionDeny {
t.Errorf("expected Deny for disable_logging, got %s", decision.Decision)
}
}

// TestPolicyEngineBlocksSelfPolicyModification verifies that policy modification is always blocked.
func TestPolicyEngineBlocksSelfPolicyModification(t *testing.T) {
logger := zap.NewNop()
engine, err := policyengine.NewEngine(policyengine.Config{PolicyDir: "../../policies"}, logger)
if err != nil {
t.Fatalf("failed to create policy engine: %v", err)
}
ctx := context.Background()
event := map[string]interface{}{
"event_id": "test-002",
"domain":   "agent",
}
decision := engine.Evaluate(ctx, event, "modify_policy")
if decision.Decision != policyengine.DecisionDeny {
t.Errorf("expected Deny for modify_policy, got %s", decision.Decision)
}
if !decision.ConstitutionalViolation {
t.Error("expected ConstitutionalViolation=true for modify_policy")
}
}

// TestPolicyEngineFailSafeDefault verifies that unknown actions are denied by default.
func TestPolicyEngineFailSafeDefault(t *testing.T) {
logger := zap.NewNop()
engine, err := policyengine.NewEngine(policyengine.Config{PolicyDir: "../../policies"}, logger)
if err != nil {
t.Fatalf("failed to create policy engine: %v", err)
}
ctx := context.Background()
event := map[string]interface{}{
"event_id": "test-003",
"domain":   "host",
}
decision := engine.Evaluate(ctx, event, "unknown_action_xyz")
if decision.Decision != policyengine.DecisionDeny {
t.Errorf("expected Deny (fail-safe) for unknown action, got %s", decision.Decision)
}
}

// ---- Audit ledger tamper-evidence ----

// TestAuditLedgerTamperEvidence verifies that the SHA-256 chain detects modifications.
func TestAuditLedgerTamperEvidence(t *testing.T) {
logger := zap.NewNop()
ledger := auditled.NewLedger(auditled.Config{}, logger)
ctx := context.Background()

inputs := []auditled.AuditEntry{
{EventID: "e1", Actor: "test", Action: "allow", Decision: "allow"},
{EventID: "e2", Actor: "test", Action: "deny", Decision: "deny"},
{EventID: "e3", Actor: "test", Action: "block", Decision: "deny"},
}
for _, e := range inputs {
entry := e
if err := ledger.Append(ctx, entry); err != nil {
t.Fatalf("append failed: %v", err)
}
}

// Retrieve entries from in-memory cache and verify chain integrity.
chain := ledger.Entries()
if len(chain) != len(inputs) {
t.Fatalf("expected %d entries, got %d", len(inputs), len(chain))
}
if err := auditled.VerifyChain(chain); err != nil {
t.Errorf("VerifyChain failed on unmodified chain: %v", err)
}

// Tamper with one entry and verify detection.
tampered := make([]auditled.AuditEntry, len(chain))
copy(tampered, chain)
tampered[1].Action = "tampered-action"
if err := auditled.VerifyChain(tampered); err == nil {
t.Error("expected VerifyChain to detect tampering, but it did not")
}
}
