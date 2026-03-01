# OpenGuard v5 — Product Requirements Document

## Executive Summary

OpenGuard v5 is a constitutional, policy-governed defensive platform by DSHub Ltd. It provides real-time threat detection, AI agent supervision, and multi-channel communication monitoring across enterprise environments. Every action taken by the platform is governed by an immutable constitutional policy layer, ensuring humans remain in control of all high-impact decisions.

---

## Mission

To protect organizations from endpoint threats, communication-based attacks, and AI agent misbehaviour by providing a composable, transparent, and auditable security platform that is itself AI-assisted but never AI-controlled.

---

## Core Constitution (10 Principles)

| # | Principle | Enforcement |
|---|-----------|-------------|
| 1 | **Safety over autonomy** | Hard — any conflict with safety constraints → block |
| 2 | **Least privilege by default** | Hard — minimum permissions; deny excess |
| 3 | **Human override always** | Hard — pause/stop/audit must always be available |
| 4 | **No stealth actions; full auditability** | Hard — every action logged with SHA-256 chain |
| 5 | **Privacy-first** | Soft — metadata over content; alert on content access |
| 6 | **Policy-bound execution** | Hard — deny/ask/allow; no ad-hoc actions |
| 7 | **Fail-safe on uncertainty** | Hard — default to block when confidence < threshold |
| 8 | **No self-policy modification** | Hard — policies are immutable at runtime |
| 9 | **Defense-in-depth** | Soft — multiple independent control layers required |
| 10 | **Explainability** | Hard for T2+ — evidence, confidence, citation, blast-radius |

---

## Functional Domains

### HostGuard
Monitors operating-system level behaviour: process tree anomalies, privilege escalation attempts, unusual binary execution, and resource abuse.

### CommsGuard
Monitors communication channels (WhatsApp, Telegram, Facebook Messenger, Twilio SMS/Voice) for phishing, credential harvesting, data exfiltration, and social engineering patterns.

### AgentGuard
Supervises AI agents deployed within the organization: detects unsanctioned external outreach, tool-use outside approved scope, and attempts to modify their own operational policies.

### ModelGuard
Governs the Model Abstraction Layer (MAL): routes prompts to appropriate AI providers, enforces prompt/output guardrails, manages quorum for high-risk decisions, and audits all model interactions.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Go 1.22 |
| Messaging bus | NATS |
| Metrics | Prometheus |
| Tracing | OpenTelemetry |
| Logging | zap (structured) |
| Storage | Append-only NDJSON (audit), configurable backend |
| Model Providers | OpenAI Codex, Anthropic Claude, Google Gemini |

---

## Multi-Model Architecture

### Model Abstraction Layer (MAL)
The MAL exposes a single `ModelProvider` interface that all AI provider adapters implement. Services interact only with the MAL — never directly with external model APIs.

### Routing Strategy

| Risk Level | Strategy |
|------------|---------|
| Low | Single provider — cheapest/fastest |
| Medium | Primary provider with automatic fallback |
| High / Critical | Two-provider quorum — both must agree; flag for human approval |

### Guardrails (Non-Negotiable)
- Models CANNOT directly execute actions.
- All proposed actions pass through the Policy Engine before execution.
- Prompt content is sanitized before dispatch.
- Output is validated against schema before use.

---

## Risk & Response Model

### Tier Definitions

| Tier | Risk Score | Description |
|------|-----------|-------------|
| T0 | 0–19 | Informational — log only |
| T1 | 20–39 | Low — alert notification |
| T2 | 40–59 | Medium — hold action, request human approval |
| T3 | 60–79 | High — execute containment (isolate, revoke, disable) |
| T4 | 80–100 | Critical — pre-authorized emergency lockdown only |

### Composite Risk Score

```
R = anomaly_score + policy_violation_score + threat_intel_score + asset_criticality_score
```

Each component is normalized to 0–25; R is clamped to [0, 100].

---

## Baseline Policy

### Always Block
- Self-policy edits at runtime
- Disabling or bypassing logging/audit
- Outbound transmission of secrets or credentials
- Unapproved privilege escalation

### Require Approval
- Bulk outbound communication (>100 recipients)
- First-time recipient with attachment
- Token or credential revocation
- Process termination on critical services
- Emergency lockdown activation

### Auto-Allow
- Signed, templated communications to allowlisted recipients
- Low-risk repetitive workflows within established quota
- Read-only operations on non-sensitive resources

---

## Compliance & Privacy

- GDPR/CCPA: metadata-first collection; content access requires justification and logging.
- SOC 2: full audit trail, access controls, encryption at rest and in transit.
- ISO 27001: defense-in-depth controls aligned to Annex A.

---

## Production Readiness Checklist

- [ ] All constitutional rules encoded in `policies/constitution.yaml`
- [ ] All baseline policies encoded in `policies/openguard-v5.yaml`
- [ ] Detection rules validated against test corpus
- [ ] Model provider API keys rotated and stored in secrets manager
- [ ] JWT secret rotated; HS256 minimum
- [ ] Audit ledger backup configured
- [ ] NATS cluster deployed with persistence enabled
- [ ] Prometheus + Grafana dashboards deployed
- [ ] Runbooks reviewed and rehearsed
- [ ] Human override tested in staging
- [ ] Penetration test completed before go-live
