package toolcheck

import (
	"os"
	"testing"

	"go.uber.org/zap"
)

func newTestChecker(t *testing.T, policies *PolicyConfig) *ToolIntentChecker {
	t.Helper()
	checker, err := New(Config{Policies: policies}, zap.NewNop())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	return checker
}

func TestCheck_ApprovedTools(t *testing.T) {
	checker := newTestChecker(t, &PolicyConfig{
		Agents: []AgentToolPolicy{
			{ID: "agent-finance", ApprovedTools: []string{"read_database", "generate_report"}},
		},
	})

	if err := checker.Check("agent-finance", []string{"read_database", "generate_report"}); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestCheck_DisallowedTool(t *testing.T) {
	checker := newTestChecker(t, &PolicyConfig{
		Agents: []AgentToolPolicy{
			{ID: "agent-finance", ApprovedTools: []string{"read_database"}},
		},
	})

	err := checker.Check("agent-finance", []string{"read_database", "delete_records"})
	if err == nil {
		t.Fatal("expected error for disallowed tool")
	}
	if !IsToolViolation(err) {
		t.Fatalf("expected ToolViolation, got %T: %v", err, err)
	}
	v := err.(*ToolViolation)
	if v.AgentID != "agent-finance" {
		t.Errorf("expected agent_id %q, got %q", "agent-finance", v.AgentID)
	}
	if v.ToolName != "delete_records" {
		t.Errorf("expected tool_name %q, got %q", "delete_records", v.ToolName)
	}
}

func TestCheck_NoPolicy_PermitsAll(t *testing.T) {
	checker := newTestChecker(t, &PolicyConfig{
		Agents: []AgentToolPolicy{
			{ID: "agent-finance", ApprovedTools: []string{"read_database"}},
		},
	})

	// agent-unknown has no policy entry → should permit all tools.
	if err := checker.Check("agent-unknown", []string{"any_tool", "another_tool"}); err != nil {
		t.Fatalf("expected no error for agent with no policy, got %v", err)
	}
}

func TestCheck_EmptyToolCalls(t *testing.T) {
	checker := newTestChecker(t, &PolicyConfig{
		Agents: []AgentToolPolicy{
			{ID: "agent-finance", ApprovedTools: []string{"read_database"}},
		},
	})

	if err := checker.Check("agent-finance", []string{}); err != nil {
		t.Fatalf("expected no error for empty tool calls, got %v", err)
	}
}

func TestCheck_NilPolicies(t *testing.T) {
	checker := newTestChecker(t, nil)
	// No policies configured — all agents permit all tools.
	if err := checker.Check("agent-x", []string{"any_tool"}); err != nil {
		t.Fatalf("expected no error with nil policies, got %v", err)
	}
}

func TestNew_PolicyFile(t *testing.T) {
	// Write a temporary YAML file.
	tmp := t.TempDir() + "/agent-tools.yaml"
	content := []byte(`agents:
  - id: "agent-test"
    approved_tools:
      - "safe_tool"
`)
	if err := os.WriteFile(tmp, content, 0o600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	checker, err := New(Config{PolicyPath: tmp}, zap.NewNop())
	if err != nil {
		t.Fatalf("New with file path failed: %v", err)
	}

	if err := checker.Check("agent-test", []string{"safe_tool"}); err != nil {
		t.Fatalf("expected safe_tool to be approved, got %v", err)
	}
	if err := checker.Check("agent-test", []string{"unsafe_tool"}); err == nil {
		t.Fatal("expected error for unsafe_tool")
	}
}

func TestNew_MissingFile(t *testing.T) {
	_, err := New(Config{PolicyPath: "/nonexistent/path/agent-tools.yaml"}, zap.NewNop())
	if err == nil {
		t.Fatal("expected error for missing policy file")
	}
}
