// Package claude provides an Anthropic Claude implementation of the ModelProvider interface.
package claude

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.uber.org/zap"

	mg "github.com/DiniMuhd7/openguard/model-gateway/interfaces"
)

const (
	defaultBaseURL    = "https://api.anthropic.com"
	defaultVersion    = "2023-06-01"
	defaultModel      = "claude-3-5-sonnet-20241022"
	defaultMaxRetries = 3
	defaultTimeout    = 30 * time.Second
)

// Config holds configuration for the Claude provider.
type Config struct {
	// APIKey is the Anthropic API key.
	APIKey string
	// BaseURL overrides the default Anthropic API base URL.
	BaseURL string
	// Version is the Anthropic API version header value.
	Version string
	// Model specifies which Claude model to use.
	Model string
	// MaxRetries is the number of retry attempts on transient errors.
	MaxRetries int
	// Timeout is the HTTP request timeout.
	Timeout time.Duration
}

// ClaudeProvider implements mg.ModelProvider for Anthropic Claude models.
type ClaudeProvider struct {
	apiKey     string
	baseURL    string
	version    string
	model      string
	maxRetries int
	httpClient *http.Client
	logger     *zap.Logger
}

// NewClaudeProvider constructs a new ClaudeProvider with the given configuration.
func NewClaudeProvider(cfg Config, logger *zap.Logger) *ClaudeProvider {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	version := cfg.Version
	if version == "" {
		version = defaultVersion
	}
	model := cfg.Model
	if model == "" {
		model = defaultModel
	}
	maxRetries := cfg.MaxRetries
	if maxRetries == 0 {
		maxRetries = defaultMaxRetries
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	return &ClaudeProvider{
		apiKey:     cfg.APIKey,
		baseURL:    baseURL,
		version:    version,
		model:      model,
		maxRetries: maxRetries,
		httpClient: &http.Client{Timeout: timeout},
		logger:     logger,
	}
}

// ProviderName returns the canonical provider identifier.
func (p *ClaudeProvider) ProviderName() string {
	return "anthropic-claude"
}

// HealthCheck verifies the provider is reachable.
func (p *ClaudeProvider) HealthCheck(ctx context.Context) error {
	_, err := p.complete(ctx, "Respond with OK")
	if err != nil {
		return fmt.Errorf("claude: health check: %w", err)
	}
	return nil
}

// Analyze performs event analysis using the Anthropic Messages API.
func (p *ClaudeProvider) Analyze(ctx context.Context, eventCtx mg.EventContext) (*mg.AnalysisResult, error) {
	prompt := fmt.Sprintf(
		"You are a security analyst. Analyze the following security event and return a JSON object with fields: summary (string), confidence (float 0-1), risk_level (low|medium|high|critical), details (object).\n\nEvent:\n%s\n\nIndicators: %v",
		eventCtx.RawPayload, eventCtx.Indicators,
	)
	raw, err := p.complete(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("claude: analyze: %w", err)
	}
	var result struct {
		Summary    string            `json:"summary"`
		Confidence float64           `json:"confidence"`
		RiskLevel  string            `json:"risk_level"`
		Details    map[string]string `json:"details"`
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return &mg.AnalysisResult{
			ProviderName: p.ProviderName(),
			Summary:      raw,
			Confidence:   0.5,
			RiskLevel:    mg.RiskMedium,
		}, nil
	}
	return &mg.AnalysisResult{
		ProviderName: p.ProviderName(),
		Summary:      result.Summary,
		Confidence:   result.Confidence,
		RiskLevel:    mg.RiskLevel(result.RiskLevel),
		Details:      result.Details,
	}, nil
}

// Classify assesses the risk level for the given risk context.
func (p *ClaudeProvider) Classify(ctx context.Context, riskCtx mg.RiskContext) (*mg.ClassificationResult, error) {
	prompt := fmt.Sprintf(
		"Classify the risk level and return JSON: risk_level (low|medium|high|critical), risk_score (0-100), confidence (0-1), rationale (string).\n\nAnomaly: %.2f, PolicyViolation: %.2f, ThreatIntel: %.2f, AssetCriticality: %.2f\nContext: %s",
		riskCtx.AnomalyScore, riskCtx.PolicyViolationScore, riskCtx.ThreatIntelScore, riskCtx.AssetCriticalityScore, riskCtx.Context,
	)
	raw, err := p.complete(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("claude: classify: %w", err)
	}
	var result struct {
		RiskLevel  string  `json:"risk_level"`
		RiskScore  float64 `json:"risk_score"`
		Confidence float64 `json:"confidence"`
		Rationale  string  `json:"rationale"`
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return &mg.ClassificationResult{
			ProviderName: p.ProviderName(),
			RiskLevel:    mg.RiskMedium,
			RiskScore:    50,
			Confidence:   0.5,
			Rationale:    raw,
		}, nil
	}
	return &mg.ClassificationResult{
		ProviderName: p.ProviderName(),
		RiskLevel:    mg.RiskLevel(result.RiskLevel),
		RiskScore:    result.RiskScore,
		Confidence:   result.Confidence,
		Rationale:    result.Rationale,
	}, nil
}

// ProposeActions generates recommended response actions for an incident.
func (p *ClaudeProvider) ProposeActions(ctx context.Context, incidentCtx mg.IncidentContext) (*mg.ActionProposal, error) {
	prompt := fmt.Sprintf(
		"Propose response actions for this security incident. Return JSON: actions (array of {id,type,target,rationale,risk_if_not_taken}), blast_radius (string), rollback_plan (string), requires_human_approval (bool).\n\nIncident: %s\nTier: %s\nRisk Score: %.2f\nAffected: %v",
		incidentCtx.EventSummary, incidentCtx.Tier, incidentCtx.RiskScore, incidentCtx.AffectedResources,
	)
	raw, err := p.complete(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("claude: propose actions: %w", err)
	}
	var result struct {
		Actions []struct {
			ID             string `json:"id"`
			Type           string `json:"type"`
			Target         string `json:"target"`
			Rationale      string `json:"rationale"`
			RiskIfNotTaken string `json:"risk_if_not_taken"`
		} `json:"actions"`
		BlastRadius           string `json:"blast_radius"`
		RollbackPlan          string `json:"rollback_plan"`
		RequiresHumanApproval bool   `json:"requires_human_approval"`
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return &mg.ActionProposal{
			ProviderName:          p.ProviderName(),
			BlastRadius:           "unknown",
			RollbackPlan:          raw,
			RequiresHumanApproval: true,
		}, nil
	}
	actions := make([]mg.ProposedAction, 0, len(result.Actions))
	for _, a := range result.Actions {
		actions = append(actions, mg.ProposedAction{
			ID:             a.ID,
			Type:           a.Type,
			Target:         a.Target,
			Rationale:      a.Rationale,
			RiskIfNotTaken: a.RiskIfNotTaken,
		})
	}
	return &mg.ActionProposal{
		ProviderName:          p.ProviderName(),
		Actions:               actions,
		BlastRadius:           result.BlastRadius,
		RollbackPlan:          result.RollbackPlan,
		RequiresHumanApproval: result.RequiresHumanApproval,
	}, nil
}

// Explain generates a human-readable explanation for a decision.
func (p *ClaudeProvider) Explain(ctx context.Context, decisionCtx mg.DecisionContext) (*mg.Explanation, error) {
	prompt := fmt.Sprintf(
		"Explain this security decision in plain language. Return JSON: evidence_summary (string), confidence_score (0-1), blast_radius_estimate (string), rollback_plan (string).\n\nDecision: %s\nAction: %s\nPolicies: %v\nRisk Score: %.2f",
		decisionCtx.DecisionID, decisionCtx.Action, decisionCtx.PolicyCitations, decisionCtx.RiskScore,
	)
	raw, err := p.complete(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("claude: explain: %w", err)
	}
	var result struct {
		EvidenceSummary     string  `json:"evidence_summary"`
		ConfidenceScore     float64 `json:"confidence_score"`
		BlastRadiusEstimate string  `json:"blast_radius_estimate"`
		RollbackPlan        string  `json:"rollback_plan"`
	}
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return &mg.Explanation{
			ProviderName:    p.ProviderName(),
			DecisionID:      decisionCtx.DecisionID,
			EvidenceSummary: raw,
			PolicyCitations: decisionCtx.PolicyCitations,
			ConfidenceScore: 0.5,
		}, nil
	}
	return &mg.Explanation{
		ProviderName:        p.ProviderName(),
		DecisionID:          decisionCtx.DecisionID,
		EvidenceSummary:     result.EvidenceSummary,
		PolicyCitations:     decisionCtx.PolicyCitations,
		ConfidenceScore:     result.ConfidenceScore,
		BlastRadiusEstimate: result.BlastRadiusEstimate,
		RollbackPlan:        result.RollbackPlan,
	}, nil
}

// complete sends a message to the Anthropic Messages API with retry logic.
func (p *ClaudeProvider) complete(ctx context.Context, prompt string) (string, error) {
	body, err := json.Marshal(map[string]interface{}{
		"model":      p.model,
		"max_tokens": 1024,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	})
	if err != nil {
		return "", fmt.Errorf("claude: marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < p.maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/v1/messages", bytes.NewReader(body))
		if err != nil {
			return "", fmt.Errorf("claude: create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", p.apiKey)
		req.Header.Set("anthropic-version", p.version)

		resp, err := p.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("claude: http request (attempt %d): %w", attempt+1, err)
			p.logger.Warn("claude: request failed, retrying", zap.Int("attempt", attempt+1), zap.Error(err))
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			lastErr = fmt.Errorf("claude: rate limited (attempt %d)", attempt+1)
			p.logger.Warn("claude: rate limited", zap.Int("attempt", attempt+1))
			continue
		}
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return "", fmt.Errorf("claude: unexpected status %d: %s", resp.StatusCode, string(b))
		}

		var response struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return "", fmt.Errorf("claude: decode response: %w", err)
		}
		for _, block := range response.Content {
			if block.Type == "text" {
				return block.Text, nil
			}
		}
		return "", fmt.Errorf("claude: no text content in response")
	}
	return "", fmt.Errorf("claude: all retries exhausted: %w", lastErr)
}
