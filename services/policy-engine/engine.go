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
	// AIAssessment is the Layer 0 model provider output attached to this decision.
	// It is nil when no assessment was provided to Evaluate.
	AIAssessment *AIAssessment
}

// constitutionPrinciple is the YAML structure of a constitutional principle.
type constitutionPrinciple struct {
	ID               string `yaml:"id"`
	Name             string `yaml:"name"`
	Description      string `yaml:"description"`
	EnforcementLevel string `yaml:"enforcement_level"`
	ViolationAction  string `yaml:"violation_action"`
}

// aiProviderConfig holds the Layer 0 AI provider settings from constitution.yaml.
type aiProviderConfig struct {
	Role             string   `yaml:"role"`
	EvaluationOrder  int      `yaml:"evaluation_order"`
	EnforcementLevel string   `yaml:"enforcement_level"`
	OnProviderFailure string  `yaml:"on_provider_failure"`
	Capabilities     []string `yaml:"capabilities"`
	OutputFields     []string `yaml:"output_fields"`
}

// constitutionFile is the top-level YAML structure of constitution.yaml.
type constitutionFile struct {
	Version    string              `yaml:"version"`
	AIProvider aiProviderConfig    `yaml:"ai_provider"`
	Principles []constitutionPrinciple `yaml:"principles"`
}

// AIAssessment carries the pre-computed AI model provider output for a given
// event.  It is produced by the model-gateway and injected into Evaluate as
// Layer 0 — before any constitutional principle or baseline policy is applied.
// All fields are optional; an absent assessment is treated as maximum
// uncertainty (constitutional principle C-007).
type AIAssessment struct {
	// RiskLevel is the AI-assigned risk level: critical, high, medium, or low.
	RiskLevel string
	// Confidence is the model's confidence in its assessment (0.0 – 1.0).
	Confidence float64
	// Indicators are novel threat indicators surfaced by the model.
	Indicators []string
	// Summary is a human-readable narrative produced by the model.
	Summary string
	// RecommendedAction is the model's suggested policy action: block, escalate, or allow.
	RecommendedAction string
	// ProviderName is the name of the active model provider that produced this assessment.
	ProviderName string
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
// Evaluation follows the constitutional hierarchy:
//
//	Layer 0 — AI model provider pre-assessment (detect / assess / analyze).
//	          The ai parameter may be nil when no assessment is available;
//	          a nil assessment with a hard-enforcement ai_provider config is
//	          treated as maximum uncertainty and triggers C-007 (fail-safe).
//	Layer 1 — Constitutional principles (hard stops, C-001 … C-010).
//	Layer 2 — Baseline always-block rules.
//	Layer 3 — Baseline require-approval rules.
//	Layer 4 — Baseline auto-allow rules.
//	Default — Fail-safe deny (C-007).
//
// The engine is fully deterministic — it makes no model calls itself.
func (e *Engine) Evaluate(_ context.Context, event map[string]interface{}, proposedAction string, ai *AIAssessment) PolicyDecision {
	// ── Layer 0: AI provider pre-assessment ──────────────────────────────────
	// The AI assessment is attached to every decision for auditability (C-004).
	// When the constitution requires AI assessment (enforcement_level=hard) and
	// none is available, behaviour depends on on_provider_failure:
	//   "block"  → C-007 fail-safe deny (maximum safety, requires model-gateway).
	//   "allow"  → gracefully fall through to Layer 1 constitutional principles
	//              (graceful degradation when model-gateway is not deployed).
	if e.constitution.AIProvider.EnforcementLevel == "hard" && ai == nil {
		if e.constitution.AIProvider.OnProviderFailure == "block" {
			e.logger.Warn("policy engine: AI assessment required but absent — fail-safe deny (C-007)")
			return PolicyDecision{
				Decision:                DecisionDeny,
				PolicyCitations:         []string{"C-007", "ai_provider"},
				Rationale:               "AI model provider assessment is required by constitution (Layer 0) but was not provided; fail-safe deny (C-007)",
				ConstitutionalViolation: true,
				AIAssessment:            nil,
			}
		}
		// on_provider_failure != "block": degrade gracefully to Layer 1.
		e.logger.Debug("policy engine: AI assessment absent — falling through to Layer 1 (on_provider_failure=allow)")
	}
	// When the AI assessment recommends blocking, honour it immediately so the
	// model's threat detection can raise the effective risk before heuristic
	// rules are evaluated.  The constitutional principles still apply on top.
	if ai != nil && strings.EqualFold(ai.RecommendedAction, "block") &&
		(strings.EqualFold(ai.RiskLevel, "critical") || strings.EqualFold(ai.RiskLevel, "high")) {
		e.logger.Info("policy engine: Layer 0 AI block",
			zap.String("risk_level", ai.RiskLevel),
			zap.Float64("confidence", ai.Confidence),
			zap.String("provider", ai.ProviderName),
		)
		return PolicyDecision{
			Decision:        DecisionDeny,
			PolicyCitations: []string{"ai_provider", "C-001"},
			Rationale:       fmt.Sprintf("blocked by AI model provider (Layer 0): risk=%s confidence=%.2f — %s", ai.RiskLevel, ai.Confidence, ai.Summary),
			AIAssessment:    ai,
		}
	}

	// ── Layer 1: Constitutional principles ───────────────────────────────────
	if decision, ok := e.evaluateConstitution(event, proposedAction, ai); ok {
		decision.AIAssessment = ai
		e.logger.Info("policy engine: constitutional decision",
			zap.String("decision", string(decision.Decision)),
			zap.Strings("citations", decision.PolicyCitations),
		)
		return decision
	}

	// ── Layer 2: Always-block rules ──────────────────────────────────────────
	for _, rule := range e.baseline.AlwaysBlock {
		if e.matchesAction(proposedAction, rule) {
			return PolicyDecision{
				Decision:        DecisionDeny,
				PolicyCitations: []string{rule.ID, rule.PolicyRef},
				Rationale:       fmt.Sprintf("blocked by baseline rule %s: %s", rule.ID, rule.Description),
				AIAssessment:    ai,
			}
		}
	}

	// ── Layer 3: Require-approval rules ─────────────────────────────────────
	for _, rule := range e.baseline.RequireApproval {
		if e.matchesAction(proposedAction, rule) {
			return PolicyDecision{
				Decision:        DecisionRequireApproval,
				PolicyCitations: []string{rule.ID, rule.PolicyRef},
				Rationale:       fmt.Sprintf("approval required by rule %s: %s", rule.ID, rule.Description),
				AIAssessment:    ai,
			}
		}
	}

	// ── Layer 4: Auto-allow rules ────────────────────────────────────────────
	for _, rule := range e.baseline.AutoAllow {
		if e.matchesAction(proposedAction, rule) {
			return PolicyDecision{
				Decision:        DecisionAllow,
				PolicyCitations: []string{rule.ID, rule.PolicyRef},
				Rationale:       fmt.Sprintf("allowed by rule %s: %s", rule.ID, rule.Description),
				AIAssessment:    ai,
			}
		}
	}

	// Default: deny (fail-safe — constitutional principle C-007).
	return PolicyDecision{
		Decision:        DecisionDeny,
		PolicyCitations: []string{"C-007"},
		Rationale:       "no matching policy found; fail-safe deny (C-007: fail-safe on uncertainty)",
		AIAssessment:    ai,
	}
}

// evaluateConstitution checks an action against constitutional principles.
// Returns (decision, true) if a constitutional rule fires, (zero, false) otherwise.
func (e *Engine) evaluateConstitution(event map[string]interface{}, proposedAction string, ai *AIAssessment) (PolicyDecision, bool) {
	for _, p := range e.constitution.Principles {
		if e.violatesConstitutionalPrinciple(p, event, proposedAction, ai) {
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
// The AI assessment (Layer 0) is consulted where relevant to enrich the check.
func (e *Engine) violatesConstitutionalPrinciple(p constitutionPrinciple, _ map[string]interface{}, action string, ai *AIAssessment) bool {
	switch p.ID {
	case "C-008": // No self-policy modification.
		return strings.Contains(action, "modify_policy") || strings.Contains(action, "edit_policy")
	case "C-004": // No stealth actions.
		return strings.Contains(action, "disable_logging") || strings.Contains(action, "disable_audit")
	case "C-002": // Least privilege.
		return strings.Contains(action, "grant_admin") && !strings.Contains(action, "approved")
	case "C-007": // Fail-safe on uncertainty — elevated by AI low-confidence assessment.
		// If the AI assessment signals low confidence on a non-trivial risk, treat
		// as uncertain and let C-007 block.
		if ai != nil && ai.Confidence < 0.4 &&
			(strings.EqualFold(ai.RiskLevel, "high") || strings.EqualFold(ai.RiskLevel, "critical")) {
			return true
		}
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
