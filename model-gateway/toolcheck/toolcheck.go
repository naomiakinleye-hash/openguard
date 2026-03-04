// Package toolcheck implements Stage 2 of the OpenGuard model gateway pipeline:
// Tool Intent Check. It validates proposed tool calls against a per-agent
// approved tool allowlist before dispatching to any model provider.
package toolcheck

import (
	"errors"
	"fmt"
	"os"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// ErrToolOutsideScope is returned when a proposed tool call is not in the agent's allowlist.
var ErrToolOutsideScope = errors.New("toolcheck: tool use outside approved scope")

// AgentToolPolicy defines the approved tools for a single agent.
type AgentToolPolicy struct {
	// ID is the agent identifier.
	ID string `yaml:"id"`
	// ApprovedTools is the list of tool names this agent is allowed to call.
	ApprovedTools []string `yaml:"approved_tools"`
}

// PolicyConfig is the top-level structure of the YAML allowlist file.
type PolicyConfig struct {
	Agents []AgentToolPolicy `yaml:"agents"`
}

// Config holds configuration for ToolIntentChecker.
type Config struct {
	// PolicyPath is the path to the YAML allowlist file.
	// If empty, only the inline Policies field is used.
	PolicyPath string
	// Policies provides an inline policy configuration.
	// If PolicyPath is also set, policies loaded from the file take precedence.
	Policies *PolicyConfig
	// AllowUnregisteredAgents controls whether agents with no policy entry are
	// permitted all tool calls. Defaults to false (fail-secure: deny unknown agents).
	AllowUnregisteredAgents bool
}

// ToolViolation describes a tool that was blocked.
type ToolViolation struct {
	// AgentID is the agent that attempted the tool call.
	AgentID string
	// ToolName is the name of the disallowed tool.
	ToolName string
}

// Error implements the error interface.
func (v *ToolViolation) Error() string {
	return fmt.Sprintf("toolcheck: agent %q attempted disallowed tool %q", v.AgentID, v.ToolName)
}

// ToolIntentChecker validates proposed tool calls against a per-agent allowlist.
type ToolIntentChecker struct {
	allowlists              map[string]map[string]struct{} // agentID → set of approved tool names
	allowUnregisteredAgents bool
	logger                  *zap.Logger
}

// New constructs a ToolIntentChecker from the provided Config.
// If Config.PolicyPath is set, the YAML file is loaded and takes precedence over Config.Policies.
func New(cfg Config, logger *zap.Logger) (*ToolIntentChecker, error) {
	var policyCfg *PolicyConfig

	if cfg.PolicyPath != "" {
		data, err := os.ReadFile(cfg.PolicyPath)
		if err != nil {
			return nil, fmt.Errorf("toolcheck: read policy file %q: %w", cfg.PolicyPath, err)
		}
		var loaded PolicyConfig
		if err := yaml.Unmarshal(data, &loaded); err != nil {
			return nil, fmt.Errorf("toolcheck: parse policy file %q: %w", cfg.PolicyPath, err)
		}
		policyCfg = &loaded
	} else if cfg.Policies != nil {
		policyCfg = cfg.Policies
	}

	checker := &ToolIntentChecker{
		allowlists:              make(map[string]map[string]struct{}),
		allowUnregisteredAgents: cfg.AllowUnregisteredAgents,
		logger:                  logger,
	}

	if policyCfg != nil {
		for _, agent := range policyCfg.Agents {
			tools := make(map[string]struct{}, len(agent.ApprovedTools))
			for _, t := range agent.ApprovedTools {
				tools[t] = struct{}{}
			}
			checker.allowlists[agent.ID] = tools
		}
	}

	return checker, nil
}

// Check validates that every tool in toolCalls is approved for agentID.
// If any tool is not in the allowlist, it returns a *ToolViolation error and
// the caller should emit a tool_use_outside_scope event.
// If agentID has no policy entry and AllowUnregisteredAgents is false (default),
// all tool calls are denied (fail-secure). Set AllowUnregisteredAgents: true in
// Config to restore the legacy allow-all behaviour for development.
func (c *ToolIntentChecker) Check(agentID string, toolCalls []string) error {
	approved, hasPolicy := c.allowlists[agentID]
	if !hasPolicy {
		if c.allowUnregisteredAgents {
			c.logger.Debug("toolcheck: no policy for agent, permitting all tools (allow-unregistered enabled)",
				zap.String("agent_id", agentID))
			return nil
		}
		// Fail-secure: deny all tool calls for agents with no policy.
		c.logger.Warn("toolcheck: no policy for agent, denying all tools (fail-secure)",
			zap.String("agent_id", agentID))
		if len(toolCalls) > 0 {
			return &ToolViolation{AgentID: agentID, ToolName: toolCalls[0]}
		}
		return nil
	}

	for _, tool := range toolCalls {
		if _, ok := approved[tool]; !ok {
			c.logger.Warn("toolcheck: tool use outside scope",
				zap.String("agent_id", agentID),
				zap.String("tool_name", tool),
				zap.String("indicator", "tool_use_outside_scope"),
			)
			return &ToolViolation{AgentID: agentID, ToolName: tool}
		}
	}
	return nil
}

// IsToolViolation reports whether err is a *ToolViolation.
func IsToolViolation(err error) bool {
	var v *ToolViolation
	return errors.As(err, &v)
}
