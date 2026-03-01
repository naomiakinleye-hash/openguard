// Package modelgateway defines the Model Abstraction Layer (MAL) for OpenGuard v5.
// All AI model provider adapters must implement the ModelProvider interface.
package modelgateway

import (
	"context"
	"time"
)

// RiskLevel represents the assessed risk level of an event or decision.
type RiskLevel string

const (
	// RiskLow indicates low risk — single provider, cheapest/fastest routing.
	RiskLow RiskLevel = "low"
	// RiskMedium indicates medium risk — primary provider with fallback.
	RiskMedium RiskLevel = "medium"
	// RiskHigh indicates high risk — two-provider quorum required.
	RiskHigh RiskLevel = "high"
	// RiskCritical indicates critical risk — quorum + mandatory human approval.
	RiskCritical RiskLevel = "critical"
)

// EventContext carries the context of a security event for model analysis.
type EventContext struct {
	// EventID is the unique identifier of the event.
	EventID string
	// Domain is the functional domain (host, comms, agent, model).
	Domain string
	// RawPayload is the sanitized event payload for the model.
	RawPayload string
	// Indicators are threat indicators already detected by rule-based engines.
	Indicators []string
	// Timestamp is when the event was observed.
	Timestamp time.Time
}

// RiskContext carries the context for risk classification.
type RiskContext struct {
	// EventID is the unique identifier of the event being classified.
	EventID string
	// AnomalyScore is the anomaly component of the composite risk score.
	AnomalyScore float64
	// PolicyViolationScore is the policy violation component.
	PolicyViolationScore float64
	// ThreatIntelScore is the threat intelligence component.
	ThreatIntelScore float64
	// AssetCriticalityScore is the asset criticality component.
	AssetCriticalityScore float64
	// Context is any additional textual context for classification.
	Context string
}

// IncidentContext carries incident details for action proposal generation.
type IncidentContext struct {
	// IncidentID is the unique identifier of the incident.
	IncidentID string
	// Tier is the response tier (T0–T4).
	Tier string
	// RiskScore is the composite risk score.
	RiskScore float64
	// EventSummary is a brief human-readable summary of the event.
	EventSummary string
	// AffectedResources lists resources impacted by the incident.
	AffectedResources []string
}

// DecisionContext carries the context of a decision requiring explanation.
type DecisionContext struct {
	// DecisionID is the unique identifier of the decision.
	DecisionID string
	// Action is the action taken or proposed.
	Action string
	// PolicyCitations are the policy rule IDs that drove the decision.
	PolicyCitations []string
	// RiskScore is the composite risk score at decision time.
	RiskScore float64
}

// AnalysisResult is returned by ModelProvider.Analyze.
type AnalysisResult struct {
	// ProviderName is the name of the model provider.
	ProviderName string
	// Summary is a concise analysis summary.
	Summary string
	// Confidence is the model's confidence in the analysis (0–1).
	Confidence float64
	// RiskLevel is the assessed risk level.
	RiskLevel RiskLevel
	// Details contains provider-specific analysis details.
	Details map[string]string
}

// ClassificationResult is returned by ModelProvider.Classify.
type ClassificationResult struct {
	// ProviderName is the name of the model provider.
	ProviderName string
	// RiskLevel is the classified risk level.
	RiskLevel RiskLevel
	// RiskScore is the composite score (0–100).
	RiskScore float64
	// Confidence is the classification confidence (0–1).
	Confidence float64
	// Rationale explains the classification.
	Rationale string
}

// ActionProposal is returned by ModelProvider.ProposeActions.
type ActionProposal struct {
	// ProviderName is the name of the model provider.
	ProviderName string
	// Actions is an ordered list of proposed actions.
	Actions []ProposedAction
	// BlastRadius estimates the potential impact.
	BlastRadius string
	// RollbackPlan describes how to reverse the proposed actions.
	RollbackPlan string
	// RequiresHumanApproval indicates whether human approval is needed.
	RequiresHumanApproval bool
}

// ProposedAction represents a single proposed response action.
type ProposedAction struct {
	// ID is a unique identifier for the action.
	ID string
	// Type is the action type (e.g., isolate, revoke, alert).
	Type string
	// Target identifies the resource or entity to act upon.
	Target string
	// Rationale explains why the action is recommended.
	Rationale string
	// RiskIfNotTaken estimates the risk if the action is skipped.
	RiskIfNotTaken string
}

// Explanation is returned by ModelProvider.Explain.
type Explanation struct {
	// ProviderName is the name of the model provider.
	ProviderName string
	// DecisionID ties the explanation to the decision.
	DecisionID string
	// EvidenceSummary is a human-readable summary of the evidence.
	EvidenceSummary string
	// PolicyCitations are the policies that governed the decision.
	PolicyCitations []string
	// ConfidenceScore is the model's confidence in the explanation (0–1).
	ConfidenceScore float64
	// BlastRadiusEstimate estimates the potential impact.
	BlastRadiusEstimate string
	// RollbackPlan describes how to reverse any actions taken.
	RollbackPlan string
}

// ModelProvider is the unified interface all model adapters must implement.
// Implementations must be safe for concurrent use.
type ModelProvider interface {
	// Analyze performs deep event analysis and returns a structured result.
	Analyze(ctx context.Context, eventCtx EventContext) (*AnalysisResult, error)

	// Classify assesses the risk level and score for the given risk context.
	Classify(ctx context.Context, riskCtx RiskContext) (*ClassificationResult, error)

	// ProposeActions generates a list of recommended response actions for an incident.
	ProposeActions(ctx context.Context, incidentCtx IncidentContext) (*ActionProposal, error)

	// Explain generates a human-readable explanation for a decision.
	// Required for all Tier 2+ decisions.
	Explain(ctx context.Context, decisionCtx DecisionContext) (*Explanation, error)

	// ProviderName returns the canonical name of the model provider.
	ProviderName() string

	// HealthCheck verifies that the provider is reachable and operational.
	HealthCheck(ctx context.Context) error
}
