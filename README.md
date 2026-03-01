# OpenGuard v5

**OpenGuard v5** is a constitutional, policy-governed defensive platform agent by DSHub Ltd. It monitors endpoint/system behaviour and communication channels, detects unauthorized and malicious activity, constrains and supervises AI agent behaviour, and keeps humans in control for all high-impact decisions.

---

## Functional Domains

| Domain | Component | Responsibility |
|--------|-----------|---------------|
| **HostGuard** | `rules/host/` | Process anomaly, privilege-escalation detection |
| **CommsGuard** | `rules/comms/`, `adapters/` | Phishing, exfiltration, cross-channel monitoring (WhatsApp, Telegram, Messenger, Twilio) |
| **AgentGuard** | `rules/agent/` | Unsanctioned AI agent outreach, policy compliance |
| **ModelGuard** | `model-gateway/` | Provider-agnostic MAL, routing, quorum, guardrails |

---

## Tech Stack

- **Language:** Go 1.22
- **Logging:** `go.uber.org/zap`
- **Messaging:** `github.com/nats-io/nats.go`
- **Metrics:** `github.com/prometheus/client_golang`
- **Tracing:** `go.opentelemetry.io/otel`
- **Model Providers:** OpenAI Codex, Anthropic Claude, Google Gemini

---

## Getting Started

### Prerequisites

- Go 1.22+
- NATS server (`nats-server`)

### Build

```bash
go build ./...
```

### Run

```bash
export NATS_URL=nats://localhost:4222
export POLICY_DIR=./policies
export RULES_DIR=./rules
export LISTEN_ADDR=:8080
export JWT_SECRET=your-secret-here
go run main.go
```

### Test

```bash
go test ./...
```

---

## Directory Structure

```
openguard/
  main.go                          # Entry point
  go.mod / go.sum                  # Module definition
  policies/                        # Constitutional & baseline policies
  rules/                           # Detection rules (host/comms/agent)
  model-gateway/                   # Model Abstraction Layer + providers
  services/                        # Core platform services
  adapters/                        # Communication channel adapters
  docs/                            # PRD, architecture specs, runbooks
  schemas/                         # Unified event JSON schema
  tests/                           # Contract, integration, simulation tests
```

---

## Constitutional Principles

1. **Safety over autonomy** — safety constraints always win.
2. **Least privilege by default** — minimal permissions granted.
3. **Human override always** — pause, stop, audit at any tier.
4. **No stealth actions; full auditability** — every action is logged.
5. **Privacy-first** — metadata over content collection.
6. **Policy-bound execution** — deny/ask/allow, never ad-hoc.
7. **Fail-safe on uncertainty** — default to block when unsure.
8. **No self-policy modification** — policies are immutable at runtime.
9. **Defense-in-depth** — multiple independent control layers.
10. **Explainability** — all Tier 2+ decisions include evidence + rationale.

---

## License

Proprietary — DSHub Ltd. All rights reserved.
