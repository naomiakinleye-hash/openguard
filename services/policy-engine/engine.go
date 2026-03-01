// Package policyengine implements the OpenGuard v5 deterministic policy engine.
// The engine is fully deterministic — it makes NO model calls.
// Constitutional rules are always evaluated FIRST before any other policy.
package policyengine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Config holds configuration for the policy Engine.
type Config struct {
	// PolicyDir is the directory containing policy YAML files.
	PolicyDir string
}

// DecisionType represents the outcome of a policy evaluation.
type DecisionType string

const (
	// DecisionAllow means the action is permitted by policy.
	DecisionAllow DecisionType = "allow"
	// DecisionDeny means the action is blocked by policy.
	DecisionDeny DecisionType = "deny"
	// DecisionRequireApproval means the action is held pending human approval.
	DecisionRequireApproval DecisionType = "require_approval"
)

// PolicyDecision is the result of evaluating an action against policies.
type PolicyDecision struct {
	// Decision is the policy outcome.
	Decision DecisionType
	// PolicyCitations lists the policy rule IDs that drove the decision.
	PolicyCitations []string
	// Rationale is a human-readable explanation.
	Rationale string
	// ConstitutionalViolation is true if a constitutional principle was violated.
	ConstitutionalViolation bool
}

// constitutionPrinciple is the YAML structure of a constitutional principle.
type constitutionPrinciple struct {
	ID               string `yaml:"id"`
	Name             string `yaml:"name"`
	Description      string `yaml:"description"`
	EnforcementLevel string `yaml:"enforcement_level"`
	ViolationAction  string `yaml:"violation_action"`
}

// constitutionFile is the top-level YAML structure of constitution.yaml.
type constitutionFile struct {
	Version    string                  `yaml:"version"`
	Principles []constitutionPrinciple `yaml:"principles"`
}

// baselinePolicyEntry is a single entry in the baseline policy.
type baselinePolicyEntry struct {
	ID          string                 `yaml:"id"`
	Description string                 `yaml:"description"`
	Conditions  []map[string]interface{} `yaml:"conditions"`
	Action      string                 `yaml:"action"`
	PolicyRef   string                 `yaml:"policy_ref"`
}

// baselinePolicyFile is the top-level YAML structure of openguard-v5.yaml.
type baselinePolicyFile struct {
	Version         string                `yaml:"version"`
	AlwaysBlock     []baselinePolicyEntry `yaml:"always_block"`
	RequireApproval []baselinePolicyEntry `yaml:"require_approval"`
	AutoAllow       []baselinePolicyEntry `yaml:"auto_allow"`
}

// Engine is the deterministic policy engine.
// It must NOT make any model calls — all logic is rule-based.
type Engine struct {
	cfg          Config
	constitution constitutionFile
	baseline     baselinePolicyFile
	logger       *zap.Logger
}

// NewEngine constructs a new policy Engine, loading policies from PolicyDir.
func NewEngine(cfg Config, logger *zap.Logger) (*Engine, error) {
	e := &Engine{cfg: cfg, logger: logger}
	if err := e.loadPolicies(); err != nil {
		return nil, fmt.Errorf("policy engine: load policies: %w", err)
	}
	logger.Info("policy engine: initialized",
		zap.Int("constitutional_principles", len(e.constitution.Principles)),
		zap.Int("always_block_rules", len(e.baseline.AlwaysBlock)),
		zap.Int("require_approval_rules", len(e.baseline.RequireApproval)),
		zap.Int("auto_allow_rules", len(e.baseline.AutoAllow)),
	)
	return e, nil
}

// Evaluate assesses a proposed action against all policies.
// Constitutional rules are evaluated first (hard stops).
// The engine is fully deterministic — no model calls are made.
func (e *Engine) Evaluate(_ context.Context, event map[string]interface{}, proposedAction string) PolicyDecision {
	// Step 1: Constitutional check (always first).
	if decision, ok := e.evaluateConstitution(event, proposedAction); ok {
		e.logger.Info("policy engine: constitutional decision",
			zap.String("decision", string(decision.Decision)),
			zap.Strings("citations", decision.PolicyCitations),
		)
		return decision
	}

	// Step 2: Always-block rules.
	for _, rule := range e.baseline.AlwaysBlock {
		if e.matchesAction(proposedAction, rule) {
			return PolicyDecision{
				Decision:        DecisionDeny,
				PolicyCitations: []string{rule.ID, rule.PolicyRef},
				Rationale:       fmt.Sprintf("blocked by baseline rule %s: %s", rule.ID, rule.Description),
			}
		}
	}

	// Step 3: Require-approval rules.
	for _, rule := range e.baseline.RequireApproval {
		if e.matchesAction(proposedAction, rule) {
			return PolicyDecision{
				Decision:        DecisionRequireApproval,
				PolicyCitations: []string{rule.ID, rule.PolicyRef},
				Rationale:       fmt.Sprintf("approval required by rule %s: %s", rule.ID, rule.Description),
			}
		}
	}

	// Step 4: Auto-allow rules.
	for _, rule := range e.baseline.AutoAllow {
		if e.matchesAction(proposedAction, rule) {
			return PolicyDecision{
				Decision:        DecisionAllow,
				PolicyCitations: []string{rule.ID, rule.PolicyRef},
				Rationale:       fmt.Sprintf("allowed by rule %s: %s", rule.ID, rule.Description),
			}
		}
	}

	// Default: deny (fail-safe — constitutional principle C-007).
	return PolicyDecision{
		Decision:        DecisionDeny,
		PolicyCitations: []string{"C-007"},
		Rationale:       "no matching policy found; fail-safe deny (C-007: fail-safe on uncertainty)",
	}
}

// evaluateConstitution checks an action against constitutional principles.
// Returns (decision, true) if a constitutional rule fires, (zero, false) otherwise.
func (e *Engine) evaluateConstitution(event map[string]interface{}, proposedAction string) (PolicyDecision, bool) {
	for _, p := range e.constitution.Principles {
		if e.violatesConstitutionalPrinciple(p, event, proposedAction) {
			if p.EnforcementLevel == "hard" && p.ViolationAction == "block" {
				return PolicyDecision{
					Decision:                DecisionDeny,
					PolicyCitations:         []string{p.ID},
					Rationale:               fmt.Sprintf("constitutional violation: %s — %s", p.Name, p.Description),
					ConstitutionalViolation: true,
				}, true
			}
		}
	}
	return PolicyDecision{}, false
}

// violatesConstitutionalPrinciple checks if an action violates a specific principle.
// This is a simplified implementation; production rules would be more expressive.
func (e *Engine) violatesConstitutionalPrinciple(p constitutionPrinciple, _ map[string]interface{}, action string) bool {
	switch p.ID {
	case "C-008": // No self-policy modification.
		return strings.Contains(action, "modify_policy") || strings.Contains(action, "edit_policy")
	case "C-004": // No stealth actions.
		return strings.Contains(action, "disable_logging") || strings.Contains(action, "disable_audit")
	case "C-002": // Least privilege.
		return strings.Contains(action, "grant_admin") && !strings.Contains(action, "approved")
	}
	return false
}

// matchesAction checks whether a proposed action matches a baseline policy entry.
// In production this would evaluate the conditions map against the event.
func (e *Engine) matchesAction(action string, rule baselinePolicyEntry) bool {
	for _, cond := range rule.Conditions {
		if op, ok := cond["operation"].(string); ok {
			if strings.EqualFold(action, op) {
				return true
			}
		}
	}
	return false
}

// loadPolicies loads constitution.yaml and openguard-v5.yaml from PolicyDir.
func (e *Engine) loadPolicies() error {
	constitutionPath := filepath.Join(e.cfg.PolicyDir, "constitution.yaml")
	baselinePath := filepath.Join(e.cfg.PolicyDir, "openguard-v5.yaml")

	if err := e.loadYAML(constitutionPath, &e.constitution); err != nil {
		return fmt.Errorf("load constitution: %w", err)
	}
	if err := e.loadYAML(baselinePath, &e.baseline); err != nil {
		return fmt.Errorf("load baseline: %w", err)
	}
	return nil
}

// loadYAML reads a YAML file into dest, returning nil if the file does not exist.
func (e *Engine) loadYAML(path string, dest interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			e.logger.Warn("policy engine: policy file not found", zap.String("path", path))
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}
