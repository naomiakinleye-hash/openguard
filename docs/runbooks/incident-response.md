# Incident Response Runbook

## Tier Definitions

| Tier | Risk Score | Label | Response Mode |
|------|-----------|-------|--------------|
| T0 | 0–19 | Informational | Automated — log only |
| T1 | 20–39 | Low | Automated — alert |
| T2 | 40–59 | Medium | Semi-automated — human approval required |
| T3 | 60–79 | High | Automated containment + notification |
| T4 | 80–100 | Critical | Emergency lockdown (pre-authorized) |

---

## Response Procedures

### T0 — Informational
1. Event is logged to the audit ledger.
2. No alert is sent.
3. Review in daily digest.

### T1 — Low
1. Alert sent to on-call channel (Slack/PagerDuty).
2. Event logged to audit ledger.
3. Analyst reviews within 4 hours.
4. Close or escalate.

### T2 — Medium
1. Proposed action placed on hold.
2. Human approval request sent to on-call operator.
3. 30-minute approval timeout (configurable).
4. If no response within timeout → escalate to T3 handling.
5. Operator approves or denies via Console API (`POST /api/v1/incidents/:id/approve` or `/deny`).
6. Decision logged with operator identity.

### T3 — High
1. Automated containment executed immediately:
   - Isolate affected host/process.
   - Revoke associated tokens/credentials.
   - Disable implicated service accounts.
2. Notification sent to security team lead.
3. Incident ticket created automatically.
4. Human review required within 1 hour.
5. Rollback available via Console API (`POST /api/v1/incidents/:id/override`).

### T4 — Critical
1. Pre-authorized emergency lockdown executed:
   - Network isolation of affected segment.
   - All active sessions terminated.
   - All tokens revoked.
   - System placed in read-only safe mode.
2. Immediate escalation to CISO and executive team.
3. External incident response team engaged if defined.
4. Post-incident review mandatory within 24 hours.

---

## Escalation Paths

```
T0 ──► Daily Digest
T1 ──► On-Call Analyst (Slack/PagerDuty)
T2 ──► On-Call Operator (Console API approval)
T3 ──► Security Team Lead + Incident Ticket
T4 ──► CISO + Executive Team + External IR (if configured)
```

---

## Human Override Instructions

At any tier, a human operator can:

1. **Pause** — Suspend automated response, preserving current state.
   ```
   POST /api/v1/incidents/:id/override  {"action": "pause"}
   ```

2. **Stop** — Halt all automated actions for the incident.
   ```
   POST /api/v1/incidents/:id/override  {"action": "stop"}
   ```

3. **Approve** — Explicitly approve a held action.
   ```
   POST /api/v1/incidents/:id/approve
   ```

4. **Deny** — Explicitly deny and cancel a held action.
   ```
   POST /api/v1/incidents/:id/deny
   ```

Human override is always available, including in degraded mode (no model connectivity).

---

## Rollback Procedures

Each T3/T4 action records a `rollback_plan` in the audit entry. To roll back:

1. Retrieve the rollback plan from the audit ledger.
   ```
   GET /api/v1/audit?event_id=<id>
   ```

2. Review the rollback plan with a second operator.

3. Execute rollback:
   ```
   POST /api/v1/incidents/:id/override  {"action": "rollback"}
   ```

4. Verify system state post-rollback.

5. Document rollback in incident record.

---

## Post-Incident Review

All T3 and T4 incidents require a post-incident review within:
- T3: 24 hours
- T4: 4 hours (emergency review) + 48 hours (full review)

Review must cover: timeline, root cause, response effectiveness, policy gaps, and recommended rule/policy updates.
