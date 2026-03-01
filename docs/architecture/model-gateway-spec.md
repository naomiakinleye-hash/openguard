# Model Gateway Specification

## Overview

The Model Gateway is the single interface through which all OpenGuard services interact with AI model providers. It enforces policy guardrails, routes requests based on risk level, and audits every model interaction.

---

## Model Abstraction Layer (MAL) Interface

```go
// ModelProvider is the unified interface all model adapters must implement.
type ModelProvider interface {
    Analyze(ctx context.Context, eventCtx EventContext) (*AnalysisResult, error)
    Classify(ctx context.Context, riskCtx RiskContext) (*ClassificationResult, error)
    ProposeActions(ctx context.Context, incidentCtx IncidentContext) (*ActionProposal, error)
    Explain(ctx context.Context, decisionCtx DecisionContext) (*Explanation, error)
    ProviderName() string
    HealthCheck(ctx context.Context) error
}
```

---

## Provider Adapter Contracts

Each provider adapter MUST:
1. Implement all six `ModelProvider` methods.
2. Validate inputs before dispatch.
3. Sanitize and validate outputs against the expected schema.
4. Return structured errors with provider name and operation context.
5. Respect context cancellation and deadlines.
6. Emit Prometheus metrics for latency, errors, and token usage.

---

## Routing Strategy

| Risk Level | Strategy | Providers Engaged |
|------------|---------|-----------------|
| Low | Single call — cheapest/fastest | 1 |
| Medium | Primary call with automatic fallback | Up to 2 |
| High | Two-provider quorum | 2 |
| Critical | Two-provider quorum + human approval flag | 2+ |

### Fallback Logic
- If the primary provider returns an error or times out, the router automatically retries with the next available provider.
- Fallback events are logged and incremented in metrics.
- If all providers fail, the system returns a fail-safe deny decision.

### Quorum Logic (High/Critical)
- Two providers are called concurrently.
- Both results must agree on the `RiskLevel` classification within one tier.
- If quorum is not reached, the system escalates to the next tier and flags for human approval.
- Quorum agreements are recorded in the audit ledger.

---

## Policy Check Pipeline

```
Input Prompt
    │
    ▼
┌──────────────────────────────┐
│ 1. Prompt Sanitization       │  Strip PII, credentials, disallowed content
└────────────┬─────────────────┘
             │
             ▼
┌──────────────────────────────┐
│ 2. Tool Intent Check         │  Validate proposed tool calls against allowlist
└────────────┬─────────────────┘
             │
             ▼
┌──────────────────────────────┐
│ 3. Provider Dispatch         │  Route per risk level
└────────────┬─────────────────┘
             │
             ▼
┌──────────────────────────────┐
│ 4. Output Validation         │  Schema check, confidence threshold, guardrails
└────────────┬─────────────────┘
             │
             ▼
┌──────────────────────────────┐
│ 5. Audit Logging             │  Append to audit ledger with hash chain
└──────────────────────────────┘
```

---

## Non-Negotiable Guardrails

1. Models CANNOT directly execute actions — all proposals route through the Policy Engine.
2. Prompts containing secrets, credentials, or PII are sanitized before dispatch.
3. Model outputs containing executable code are sandboxed before evaluation.
4. Every model call is audited with input hash, output hash, provider, latency, and token count.
5. A model may not propose actions that modify its own operational policies.
6. High/Critical risk decisions always require human approval regardless of quorum result.
