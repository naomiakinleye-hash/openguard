import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import type {
  ModelGuardStatsResponse,
  ModelCallEntry,
  ProviderHealthEntry,
  GuardrailConfig,
  KvStat,
  PolicyRule,
  PolicyRuleInput,
} from '../api';
import { useToast } from '../contexts/ToastContext';
import { useInterval } from '../hooks/useInterval';
import Pagination from '../components/Pagination';

// ─── Constants ────────────────────────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#d97706',
  low:      '#2563eb',
  info:     '#475569',
};
const RISK_BG: Record<string, string> = {
  critical: '#450a0a',
  high:     '#431407',
  medium:   '#422006',
  low:      '#1e3a5f',
  info:     '#1e293b',
};
const STRATEGY_COLORS: Record<string, string> = {
  single:   '#2563eb',
  fallback: '#d97706',
  quorum:   '#7c3aed',
};
const STRATEGY_BG: Record<string, string> = {
  single:   '#1e3a5f',
  fallback: '#422006',
  quorum:   '#2e1065',
};

// ─── Shared UI atoms ──────────────────────────────────────────────────────────

function StatCard({
  label,
  value,
  sub,
  color = '#2563eb',
}: {
  label: string;
  value: number | string;
  sub?: string;
  color?: string;
}) {
  return (
    <div className="card stat-card" style={{ borderLeft: `3px solid ${color}` }}>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div style={{ fontSize: '0.75rem', color: '#475569', marginTop: '0.25rem' }}>{sub}</div>}
    </div>
  );
}

function RiskBadge({ level }: { level: string }) {
  const color = RISK_COLORS[level] ?? '#475569';
  const bg    = RISK_BG[level]    ?? '#1e293b';
  return (
    <span style={{
      display: 'inline-block',
      padding: '0.125rem 0.5rem',
      borderRadius: '9999px',
      border: `1px solid ${color}`,
      background: bg,
      color,
      fontSize: '0.75rem',
      fontWeight: 700,
      textTransform: 'uppercase',
      letterSpacing: '0.05em',
    }}>
      {level}
    </span>
  );
}

function StrategyBadge({ strategy }: { strategy: string }) {
  const color = STRATEGY_COLORS[strategy] ?? '#475569';
  const bg    = STRATEGY_BG[strategy]    ?? '#1e293b';
  return (
    <span style={{
      display: 'inline-block',
      padding: '0.125rem 0.5rem',
      borderRadius: '9999px',
      border: `1px solid ${color}`,
      background: bg,
      color,
      fontSize: '0.75rem',
      fontWeight: 600,
    }}>
      {strategy}
    </span>
  );
}

function ThreatBar({ items }: { items: KvStat[] }) {
  const max = Math.max(...items.map((i) => i.count), 1);
  const palette = ['#2563eb', '#7c3aed', '#059669', '#ea580c', '#db2777', '#0891b2'];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
      {items.map((item, idx) => (
        <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span style={{ width: '8rem', fontSize: '0.75rem', color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textTransform: 'capitalize' }}>
            {item.label.replace(/-/g, ' ')}
          </span>
          <div style={{ flex: 1, height: '6px', background: '#0f172a', borderRadius: '3px', overflow: 'hidden' }}>
            <div style={{
              height: '100%',
              width: `${(item.count / max) * 100}%`,
              background: palette[idx % palette.length],
              borderRadius: '3px',
              transition: 'width 0.5s ease',
            }} />
          </div>
          <span style={{ width: '2rem', fontSize: '0.75rem', color: '#64748b', textAlign: 'right' }}>{item.count}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Provider health panel ────────────────────────────────────────────────────

function ProviderHealthPanel({ providers }: { providers: ProviderHealthEntry[] }) {
  return (
    <div className="table-card">
      <div className="table-header">Provider Health</div>
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {providers.length === 0 && (
          <div className="empty-state" style={{ padding: '1.5rem' }}>No providers found.</div>
        )}
        {providers.map((p, idx) => (
          <div key={p.id} style={{
            display: 'flex', alignItems: 'center', gap: '1rem',
            padding: '0.875rem 1.25rem',
            borderTop: idx > 0 ? '1px solid #334155' : 'none',
          }}>
            <div style={{
              width: '10px', height: '10px', borderRadius: '50%', flexShrink: 0,
              background: p.healthy ? '#4ade80' : '#dc2626',
            }} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontWeight: 600, color: '#f1f5f9', fontSize: '0.875rem' }}>{p.name}</span>
                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: p.healthy ? '#4ade80' : '#f87171' }}>
                  {p.healthy ? 'Healthy' : 'Unavailable'}
                </span>
              </div>
              {p.error && <p style={{ fontSize: '0.75rem', color: '#f87171', marginTop: '0.125rem' }}>{p.error}</p>}
              <p style={{ fontSize: '0.75rem', color: '#475569', fontFamily: 'monospace', marginTop: '0.125rem' }}>{p.id}</p>
            </div>
            <div style={{ textAlign: 'right', flexShrink: 0 }}>
              {p.healthy && (
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{p.latency_ms} ms</span>
              )}
              <p style={{ fontSize: '0.75rem', color: '#475569' }}>
                {new Date(p.last_checked).toLocaleTimeString()}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Guardrails config panel ──────────────────────────────────────────────────

function GuardrailsPanel({
  config,
  onSave,
}: {
  config: GuardrailConfig;
  onSave: (cfg: GuardrailConfig) => Promise<void>;
}) {
  const [draft, setDraft] = useState<GuardrailConfig>(config);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    setDraft(config);
  }, [config]);

  async function handleSave() {
    setSaving(true);
    await onSave(draft);
    setSaving(false);
  }

  function toggle(key: keyof GuardrailConfig) {
    setDraft((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  function setNum(key: keyof GuardrailConfig, val: string) {
    const n = parseFloat(val);
    if (!isNaN(n)) setDraft((prev) => ({ ...prev, [key]: n }));
  }

  const BoolRow = ({
    label,
    description,
    field,
  }: {
    label: string;
    description: string;
    field: keyof GuardrailConfig;
  }) => (
    <div style={{
      display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
      padding: '0.875rem 0', borderBottom: '1px solid #334155',
    }}>
      <div style={{ flex: 1, minWidth: 0, paddingRight: '1rem' }}>
        <p style={{ fontSize: '0.875rem', fontWeight: 600, color: '#f1f5f9' }}>{label}</p>
        <p style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>{description}</p>
      </div>
      <button
        onClick={() => toggle(field)}
        style={{
          position: 'relative', display: 'inline-flex', height: '1.5rem', width: '2.75rem',
          alignItems: 'center', borderRadius: '9999px', flexShrink: 0,
          background: draft[field] ? '#1d4ed8' : '#334155',
          border: 'none', cursor: 'pointer', transition: 'background 0.2s',
        }}
        role="switch"
        aria-checked={!!draft[field]}
      >
        <span style={{
          display: 'inline-block', height: '1rem', width: '1rem', borderRadius: '50%',
          background: '#f1f5f9', boxShadow: '0 1px 3px rgba(0,0,0,0.5)',
          transform: draft[field] ? 'translateX(1.5rem)' : 'translateX(0.25rem)',
          transition: 'transform 0.2s',
        }} />
      </button>
    </div>
  );

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{
        padding: '1rem 1.25rem', borderBottom: '1px solid #334155',
        display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
      }}>
        <div>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#f1f5f9' }}>Guardrail Configuration</h2>
          <p style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '0.25rem' }}>
            Changes take effect at next model call. Constitutional hard rules cannot be disabled.
          </p>
        </div>
      </div>

      <div style={{ padding: '0.5rem 1.25rem' }}>
        <BoolRow
          label="Block on Prompt Injection"
          description="Reject prompts containing known injection patterns (ignore/disregard/jailbreak). Constitutional hard rule."
          field="block_on_injection"
        />
        <BoolRow
          label="Redact Credentials"
          description="Strip AWS keys, bearer tokens, and Basic-Auth headers from prompts before dispatch."
          field="redact_credentials"
        />
        <BoolRow
          label="Redact PII"
          description="Redact email addresses, phone numbers, and credit card numbers from prompts."
          field="redact_pii"
        />

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', padding: '1rem 0', borderBottom: '1px solid #334155' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', marginBottom: '0.375rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Max Prompt Length (bytes)
            </label>
            <input
              type="number"
              min={512}
              max={32768}
              step={512}
              value={draft.max_prompt_length}
              onChange={(e) => setNum('max_prompt_length', e.target.value)}
              style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.5rem 0.75rem', fontSize: '0.875rem', color: '#e2e8f0', boxSizing: 'border-box' }}
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', marginBottom: '0.375rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Min Confidence Threshold
            </label>
            <input
              type="number"
              min={0}
              max={1}
              step={0.05}
              value={draft.min_confidence}
              onChange={(e) => setNum('min_confidence', e.target.value)}
              style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.5rem 0.75rem', fontSize: '0.875rem', color: '#e2e8f0', boxSizing: 'border-box' }}
            />
            <p style={{ fontSize: '0.75rem', color: '#475569', marginTop: '0.25rem' }}>0.0 = block nothing; 1.0 = block all uncertain</p>
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', marginBottom: '0.375rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Rate Limit (req/min)
            </label>
            <input
              type="number"
              min={1}
              max={600}
              step={1}
              value={draft.rate_limit_rpm}
              onChange={(e) => setNum('rate_limit_rpm', e.target.value)}
              style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.5rem 0.75rem', fontSize: '0.875rem', color: '#e2e8f0', boxSizing: 'border-box' }}
            />
          </div>
        </div>
      </div>

      <div style={{ padding: '1rem 1.25rem' }}>
        <button
          onClick={() => void handleSave()}
          disabled={saving}
          style={{
            padding: '0.5rem 1.25rem', borderRadius: '6px',
            background: saving ? '#334155' : '#1d4ed8',
            color: '#f1f5f9', border: 'none', cursor: saving ? 'not-allowed' : 'pointer',
            fontSize: '0.875rem', fontWeight: 600, opacity: saving ? 0.7 : 1,
          }}
        >
          {saving ? 'Saving…' : 'Save Configuration'}
        </button>
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

const ACTION_COLORS: Record<string, { color: string; bg: string; border: string }> = {
  block:            { color: '#f87171', bg: '#450a0a', border: '#dc2626' },
  require_approval: { color: '#fbbf24', bg: '#422006', border: '#d97706' },
  allow:            { color: '#4ade80', bg: '#052e16', border: '#16a34a' },
};

function ActionBadge({ action }: { action: string }) {
  const s = ACTION_COLORS[action] ?? { color: '#94a3b8', bg: '#1e293b', border: '#475569' };
  const label = action === 'require_approval' ? 'Req. Approval' : action;
  return (
    <span style={{
      display: 'inline-block', padding: '0.125rem 0.5rem',
      borderRadius: '9999px', border: `1px solid ${s.border}`,
      background: s.bg, color: s.color,
      fontSize: '0.75rem', fontWeight: 700, textTransform: 'capitalize',
      whiteSpace: 'nowrap',
    }}>
      {label}
    </span>
  );
}

// ─── PolicyEditor: inline create / edit form ─────────────────────────────────

type PolicyDraft = {
  id?: string;
  description: string;
  action: 'block' | 'require_approval' | 'allow';
  policy_ref: string;
  enabled: boolean;
  conditions: string; // newline-separated
};

const EMPTY_DRAFT: PolicyDraft = {
  description: '', action: 'block', policy_ref: '', enabled: true, conditions: '',
};

function PolicyEditorRow({
  draft,
  onChangeDraft,
  onSave,
  onCancel,
  saving,
}: {
  draft: PolicyDraft;
  onChangeDraft: (d: PolicyDraft) => void;
  onSave: () => void;
  onCancel: () => void;
  saving: boolean;
}) {
  const fieldStyle: React.CSSProperties = {
    width: '100%', background: '#0f172a', border: '1px solid #334155',
    borderRadius: '5px', padding: '0.375rem 0.625rem',
    fontSize: '0.8125rem', color: '#e2e8f0', boxSizing: 'border-box',
  };
  return (
    <tr style={{ background: '#0d1e35' }}>
      <td colSpan={6} style={{ padding: '1rem 1.25rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '0.75rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', marginBottom: '0.25rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Description *
            </label>
            <input
              style={fieldStyle}
              value={draft.description}
              onChange={(e) => onChangeDraft({ ...draft, description: e.target.value })}
              placeholder="Describe what this rule does…"
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', marginBottom: '0.25rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Policy Ref
            </label>
            <input
              style={fieldStyle}
              value={draft.policy_ref}
              onChange={(e) => onChangeDraft({ ...draft, policy_ref: e.target.value })}
              placeholder="e.g. C-001"
            />
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', marginBottom: '0.25rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Action *
            </label>
            <select
              style={{ ...fieldStyle, cursor: 'pointer' }}
              value={draft.action}
              onChange={(e) => onChangeDraft({ ...draft, action: e.target.value as PolicyDraft['action'] })}
            >
              <option value="block">Block</option>
              <option value="require_approval">Require Approval</option>
              <option value="allow">Allow</option>
            </select>
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', marginBottom: '0.25rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Conditions (one per line)
            </label>
            <textarea
              style={{ ...fieldStyle, resize: 'vertical', minHeight: '4rem' }}
              value={draft.conditions}
              onChange={(e) => onChangeDraft({ ...draft, conditions: e.target.value })}
              placeholder="e.g. action=disable_logging"
            />
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            onClick={onSave}
            disabled={saving || !draft.description.trim()}
            style={{
              padding: '0.375rem 1rem', borderRadius: '5px',
              background: saving || !draft.description.trim() ? '#334155' : '#1d4ed8',
              color: '#f1f5f9', border: 'none',
              cursor: saving || !draft.description.trim() ? 'not-allowed' : 'pointer',
              fontSize: '0.8125rem', fontWeight: 600,
            }}
          >
            {saving ? 'Saving…' : draft.id ? 'Update Rule' : 'Create Rule'}
          </button>
          <button
            onClick={onCancel}
            style={{
              padding: '0.375rem 1rem', borderRadius: '5px', background: 'none',
              color: '#64748b', border: '1px solid #334155',
              cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600,
            }}
          >
            Cancel
          </button>
        </div>
      </td>
    </tr>
  );
}

// ─── PoliciesPanel ────────────────────────────────────────────────────────────

function PoliciesPanel({
  policies,
  loading,
  onToggle,
  onSave,
  onDelete,
}: {
  policies: PolicyRule[];
  loading: boolean;
  onToggle: (rule: PolicyRule) => Promise<void>;
  onSave: (draft: PolicyDraft, original: PolicyRule | null) => Promise<void>;
  onDelete: (id: string) => Promise<void>;
}) {
  const [editingId, setEditingId] = useState<string | null>(null);
  const [draft, setDraft] = useState<PolicyDraft>(EMPTY_DRAFT);
  const [showNew, setShowNew] = useState(false);
  const [saving, setSaving] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);

  function startEdit(rule: PolicyRule) {
    setShowNew(false);
    setEditingId(rule.id);
    setDraft({ ...rule, conditions: rule.conditions.join('\n') });
  }

  function startNew() {
    setEditingId(null);
    setShowNew(true);
    setDraft(EMPTY_DRAFT);
  }

  function cancelEdit() {
    setEditingId(null);
    setShowNew(false);
    setDraft(EMPTY_DRAFT);
  }

  async function handleSave() {
    setSaving(true);
    try {
      const original = editingId ? (policies.find((p) => p.id === editingId) ?? null) : null;
      await onSave(draft, original);
      setEditingId(null);
      setShowNew(false);
      setDraft(EMPTY_DRAFT);
    } finally {
      setSaving(false);
    }
  }

  const BUILTIN_PREFIX = /^B-(BLOCK|APPROVE|ALLOW)-\d{3}$/;
  const isBuiltin = (id: string) => BUILTIN_PREFIX.test(id);

  return (
    <div className="table-card">
      <div className="table-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>Baseline Policies</span>
        <button
          onClick={startNew}
          style={{
            padding: '0.375rem 0.875rem', borderRadius: '5px',
            background: '#1d4ed8', color: '#f1f5f9', border: 'none',
            cursor: 'pointer', fontSize: '0.8125rem', fontWeight: 600,
          }}
        >
          + New Rule
        </button>
      </div>

      {loading && (
        <div className="empty-state" style={{ padding: '2rem' }}>Loading policies…</div>
      )}

      {!loading && (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ background: '#0f172a', borderBottom: '1px solid #334155' }}>
                {['ID', 'Description', 'Action', 'Policy Ref', 'Status', 'Actions'].map((h) => (
                  <th key={h} style={{
                    padding: '0.75rem 1rem', textAlign: 'left',
                    color: '#64748b', fontWeight: 600, fontSize: '0.75rem',
                    textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap',
                  }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {showNew && (
                <PolicyEditorRow
                  draft={draft}
                  onChangeDraft={setDraft}
                  onSave={() => void handleSave()}
                  onCancel={cancelEdit}
                  saving={saving}
                />
              )}
              {policies.length === 0 && !showNew && (
                <tr>
                  <td colSpan={6} className="empty-state">No policy rules found.</td>
                </tr>
              )}
              {policies.map((rule, idx) => (
                <>
                  <tr
                    key={rule.id}
                    style={{
                      borderTop: idx > 0 || showNew ? '1px solid #1e293b' : 'none',
                      opacity: rule.enabled ? 1 : 0.55,
                    }}
                  >
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: '#94a3b8' }}>{rule.id}</span>
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: '#e2e8f0', maxWidth: '22rem' }}>
                      {rule.description}
                      {rule.conditions.length > 0 && (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginTop: '0.25rem' }}>
                          {rule.conditions.map((c) => (
                            <span key={c} style={{ padding: '0.1rem 0.375rem', background: '#0f172a', border: '1px solid #334155', borderRadius: '3px', fontSize: '0.7rem', color: '#64748b', fontFamily: 'monospace' }}>
                              {c}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <ActionBadge action={rule.action} />
                    </td>
                    <td style={{ padding: '0.75rem 1rem', color: '#94a3b8', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                      {rule.policy_ref || '—'}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <button
                        onClick={() => void onToggle(rule)}
                        style={{
                          position: 'relative', display: 'inline-flex', height: '1.25rem', width: '2.25rem',
                          alignItems: 'center', borderRadius: '9999px', flexShrink: 0,
                          background: rule.enabled ? '#1d4ed8' : '#334155',
                          border: 'none', cursor: 'pointer', transition: 'background 0.2s',
                        }}
                        role="switch"
                        aria-checked={rule.enabled}
                        title={rule.enabled ? 'Disable' : 'Enable'}
                      >
                        <span style={{
                          display: 'inline-block', height: '0.875rem', width: '0.875rem',
                          borderRadius: '50%', background: '#f1f5f9',
                          transform: rule.enabled ? 'translateX(1.25rem)' : 'translateX(0.1875rem)',
                          transition: 'transform 0.2s',
                        }} />
                      </button>
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>
                      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        <button
                          onClick={() => editingId === rule.id ? cancelEdit() : startEdit(rule)}
                          style={{
                            padding: '0.25rem 0.625rem', borderRadius: '4px',
                            background: editingId === rule.id ? '#334155' : 'none',
                            border: '1px solid #334155', color: '#94a3b8',
                            cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600,
                          }}
                        >
                          {editingId === rule.id ? 'Cancel' : 'Edit'}
                        </button>
                        {!isBuiltin(rule.id) && (
                          confirmDelete === rule.id ? (
                            <div style={{ display: 'flex', gap: '0.25rem' }}>
                              <button
                                onClick={() => void onDelete(rule.id)}
                                style={{
                                  padding: '0.25rem 0.625rem', borderRadius: '4px',
                                  background: '#450a0a', border: '1px solid #dc2626',
                                  color: '#f87171', cursor: 'pointer', fontSize: '0.75rem', fontWeight: 600,
                                }}
                              >
                                Confirm
                              </button>
                              <button
                                onClick={() => setConfirmDelete(null)}
                                style={{
                                  padding: '0.25rem 0.5rem', borderRadius: '4px',
                                  background: 'none', border: '1px solid #334155',
                                  color: '#64748b', cursor: 'pointer', fontSize: '0.75rem',
                                }}
                              >
                                ✕
                              </button>
                            </div>
                          ) : (
                            <button
                              onClick={() => setConfirmDelete(rule.id)}
                              style={{
                                padding: '0.25rem 0.625rem', borderRadius: '4px',
                                background: 'none', border: '1px solid #7f1d1d',
                                color: '#f87171', cursor: 'pointer', fontSize: '0.75rem',
                              }}
                            >
                              Delete
                            </button>
                          )
                        )}
                        {isBuiltin(rule.id) && (
                          <span style={{ fontSize: '0.7rem', color: '#334155', fontStyle: 'italic' }}>built-in</span>
                        )}
                      </div>
                    </td>
                  </tr>
                  {editingId === rule.id && (
                    <PolicyEditorRow
                      key={`${rule.id}-editor`}
                      draft={draft}
                      onChangeDraft={setDraft}
                      onSave={() => void handleSave()}
                      onCancel={cancelEdit}
                      saving={saving}
                    />
                  )}
                </>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const PAGE_SIZE = 25;

export default function ModelGuard() {
  const { addToast } = useToast();

  const [stats, setStats]               = useState<ModelGuardStatsResponse | null>(null);
  const [providers, setProviders]       = useState<ProviderHealthEntry[]>([]);
  const [guardrails, setGuardrails]     = useState<GuardrailConfig | null>(null);
  const [auditEntries, setAuditEntries] = useState<ModelCallEntry[]>([]);
  const [auditTotal, setAuditTotal]     = useState(0);

  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);

  const [tab, setTab] = useState<'overview' | 'audit' | 'guardrails' | 'configuration'>('overview');

  // Audit filters
  const [auditProvider, setAuditProvider] = useState('');
  const [auditRisk, setAuditRisk]         = useState('');
  const [auditPage, setAuditPage]         = useState(1);
  const [agentSearch, setAgentSearch]     = useState('');

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, p, g] = await Promise.all([
        api.modelGuardStats(),
        api.modelGuardProviders(),
        api.modelGuardGuardrails(),
      ]);
      setStats(s);
      setProviders(p.providers ?? []);
      setGuardrails(g);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadAudit = useCallback(async () => {
    try {
      const res = await api.modelGuardAudit(
        auditProvider || undefined,
        auditRisk || undefined,
        auditPage,
      );
      setAuditEntries(res.entries ?? []);
      setAuditTotal(res.total ?? 0);
    } catch {
      setAuditEntries([]);
      setAuditTotal(0);
    }
  }, [auditProvider, auditRisk, auditPage]);

  // Configuration tab state
  const [policies, setPolicies]         = useState<PolicyRule[]>([]);
  const [policiesLoading, setPoliciesLoading] = useState(false);
  const [mgConfig, setMgConfig]         = useState<GuardrailConfig | null>(null);

  const loadConfigTab = useCallback(async () => {
    setPoliciesLoading(true);
    try {
      const [polRes, cfgRes] = await Promise.all([
        api.listPolicies(),
        api.configModelGuard(),
      ]);
      setPolicies(polRes.policies ?? []);
      setMgConfig(cfgRes);
    } catch (e) {
      addToast(e instanceof Error ? e.message : 'Failed to load configuration', 'error');
    } finally {
      setPoliciesLoading(false);
    }
  }, [addToast]);

  useEffect(() => { void loadAll(); }, [loadAll]);
  useEffect(() => {
    if (tab === 'audit') void loadAudit();
  }, [tab, loadAudit]);
  useEffect(() => {
    if (tab === 'configuration') void loadConfigTab();
  }, [tab, loadConfigTab]);

  useInterval(loadAll, 30000);

  const handleGuardrailSave = useCallback(
    async (cfg: GuardrailConfig) => {
      try {
        const res = await api.updateModelGuardGuardrails(cfg);
        setGuardrails(res.config);
        addToast('Guardrail configuration saved', 'success');
      } catch (e) {
        addToast(e instanceof Error ? e.message : 'Save failed', 'error');
      }
    },
    [addToast],
  );

  const handleMgConfigSave = useCallback(
    async (cfg: GuardrailConfig) => {
      try {
        await api.updateModelGuardConfig(cfg);
        setMgConfig(cfg);
        addToast('ModelGuard configuration saved', 'success');
      } catch (e) {
        addToast(e instanceof Error ? e.message : 'Save failed', 'error');
      }
    },
    [addToast],
  );

  const handlePolicyToggle = useCallback(
    async (rule: PolicyRule) => {
      try {
        await api.updatePolicy(rule.id, { ...rule, enabled: !rule.enabled });
        setPolicies((prev) => prev.map((p) => p.id === rule.id ? { ...p, enabled: !p.enabled } : p));
        addToast(`Policy ${rule.id} ${!rule.enabled ? 'enabled' : 'disabled'}`, 'success');
      } catch (e) {
        addToast(e instanceof Error ? e.message : 'Update failed', 'error');
      }
    },
    [addToast],
  );

  const handlePolicySave = useCallback(
    async (draft: PolicyDraft, original: PolicyRule | null) => {
      const rule: PolicyRuleInput = {
        description: draft.description,
        action: draft.action,
        policy_ref: draft.policy_ref,
        enabled: draft.enabled,
        conditions: draft.conditions.split('\n').map((s) => s.trim()).filter(Boolean),
      };
      try {
        if (original) {
          await api.updatePolicy(original.id, rule);
          setPolicies((prev) =>
            prev.map((p) =>
              p.id === original.id
                ? { ...p, ...rule, id: p.id, conditions: rule.conditions ?? [] }
                : p,
            ),
          );
          addToast('Policy updated', 'success');
        } else {
          const res = await api.createPolicy(rule);
          addToast(`Policy ${res.id} created`, 'success');
          void loadConfigTab();
        }
      } catch (e) {
        addToast(e instanceof Error ? e.message : 'Save failed', 'error');
        throw e; // re-throw so PolicyEditorRow knows it failed
      }
    },
    [addToast, loadConfigTab],
  );

  const handlePolicyDelete = useCallback(
    async (id: string) => {
      try {
        await api.deletePolicy(id);
        setPolicies((prev) => prev.filter((p) => p.id !== id));
        addToast(`Policy ${id} deleted`, 'success');
      } catch (e) {
        addToast(e instanceof Error ? e.message : 'Delete failed', 'error');
      }
    },
    [addToast],
  );

  const blockedPct =
    stats && stats.total_calls > 0
      ? ((stats.blocked_calls / stats.total_calls) * 100).toFixed(1)
      : '0';

  const totalAuditPages = Math.ceil((auditTotal || 0) / PAGE_SIZE);

  const displayedAudit = agentSearch
    ? auditEntries.filter((e) => e.agent_id.toLowerCase().includes(agentSearch.toLowerCase()))
    : auditEntries;

  if (loading && !stats) {
    return (
      <div style={{ padding: '2rem' }}>
        <div className="card-grid" style={{ marginBottom: '1rem' }}>
          {[0, 1, 2, 3, 4].map((i) => (
            <div key={i} className="card loading-skeleton" style={{ height: '5rem' }} />
          ))}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1rem' }}>
          <div className="card loading-skeleton" style={{ height: '16rem' }} />
          <div className="card loading-skeleton" style={{ height: '16rem' }} />
        </div>
      </div>
    );
  }

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* ─── Header ───────────────────────────────────────────────────────────── */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h2>🧠 ModelGuard</h2>
          <p>Model Abstraction Layer — routing, guardrails, and full model call auditing</p>
        </div>
        <button
          onClick={() => void loadAll()}
          disabled={loading}
          className="btn-secondary"
          style={{ fontSize: '0.875rem', fontWeight: 600, opacity: loading ? 0.5 : 1 }}
        >
          {loading ? '…' : '↻ Refresh'}
        </button>
      </div>

      {error && (
        <div className="error-msg" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>{error}</span>
          <button onClick={() => void loadAll()} style={{ marginLeft: '1rem', background: 'none', border: 'none', color: '#fca5a5', cursor: 'pointer', fontWeight: 600, textDecoration: 'underline' }}>
            Retry
          </button>
        </div>
      )}

      {/* ─── Stats strip ──────────────────────────────────────────────────────── */}
      <div className="card-grid">
        <StatCard label="Total Calls"      value={stats?.total_calls ?? 0}                             sub={stats?.period ?? '24h'} color="#2563eb" />
        <StatCard label="Blocked"          value={stats?.blocked_calls ?? 0}                           sub={`${blockedPct}% of total`} color="#dc2626" />
        <StatCard label="Avg Latency"      value={`${stats?.avg_latency_ms ?? 0} ms`}                  color="#ea580c" />
        <StatCard label="Avg Tokens"       value={(stats?.avg_token_count ?? 0).toLocaleString()}      color="#7c3aed" />
        <StatCard label="Avg Confidence"   value={`${((stats?.avg_confidence ?? 0) * 100).toFixed(0)}%`} color="#059669" />
      </div>

      {/* ─── Tabs ─────────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: '2rem', borderBottom: '1px solid #334155', paddingBottom: '0' }}>
        {(['overview', 'audit', 'guardrails', 'configuration'] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              paddingBottom: '0.75rem',
              fontSize: '0.875rem', fontWeight: 600,
              color: tab === t ? '#60a5fa' : '#64748b',
              borderBottom: tab === t ? '2px solid #3b82f6' : '2px solid transparent',
            }}
          >
            {t === 'overview' ? 'Overview'
              : t === 'audit' ? 'Model Call Audit'
              : t === 'guardrails' ? 'Guardrails'
              : 'Configuration'}
          </button>
        ))}
      </div>

      {/* ─── Tab: Overview ────────────────────────────────────────────────────── */}
      {tab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1.5rem' }}>
          {/* Provider health */}
          <div>
            <ProviderHealthPanel providers={providers} />
          </div>

          {/* Breakdown charts */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div className="card">
              <p className="section-title" style={{ marginBottom: '1rem' }}>Calls by Provider</p>
              {stats?.provider_breakdown && stats.provider_breakdown.length > 0
                ? <ThreatBar items={stats.provider_breakdown} />
                : <p style={{ fontSize: '0.875rem', color: '#475569' }}>No data</p>}
            </div>

            <div className="card">
              <p className="section-title" style={{ marginBottom: '1rem' }}>Calls by Strategy</p>
              {stats?.strategy_breakdown && stats.strategy_breakdown.length > 0
                ? <ThreatBar items={stats.strategy_breakdown} />
                : <p style={{ fontSize: '0.875rem', color: '#475569' }}>No data</p>}
            </div>

            <div className="card">
              <p className="section-title" style={{ marginBottom: '1rem' }}>Calls by Risk Level</p>
              {stats?.risk_breakdown && stats.risk_breakdown.length > 0
                ? <ThreatBar items={stats.risk_breakdown} />
                : <p style={{ fontSize: '0.875rem', color: '#475569' }}>No data</p>}
            </div>

            <div className="card">
              <p className="section-title" style={{ marginBottom: '1rem' }}>Pipeline Stages</p>
              <ol style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', listStyle: 'none', padding: 0, margin: 0 }}>
                {[
                  { label: 'Prompt Sanitization',  desc: 'Strip PII, credentials, injection patterns',           color: '#2563eb' },
                  { label: 'Tool Intent Check',     desc: 'Validate tool calls against agent allowlist',          color: '#7c3aed' },
                  { label: 'Provider Dispatch',     desc: 'Route by risk level — single / fallback / quorum',     color: '#059669' },
                  { label: 'Output Validation',     desc: 'Schema check, confidence threshold, guardrails',       color: '#ea580c' },
                  { label: 'Audit Logging',         desc: 'Append tamper-evident record with SHA-256 hash',       color: '#64748b' },
                ].map((stage, idx) => (
                  <li key={stage.label} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem' }}>
                    <div style={{
                      width: '1.5rem', height: '1.5rem', borderRadius: '50%',
                      background: stage.color, color: '#fff',
                      fontSize: '0.75rem', fontWeight: 700,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      flexShrink: 0, marginTop: '0.125rem',
                    }}>
                      {idx + 1}
                    </div>
                    <div>
                      <p style={{ fontSize: '0.875rem', fontWeight: 600, color: '#f1f5f9' }}>{stage.label}</p>
                      <p style={{ fontSize: '0.75rem', color: '#64748b' }}>{stage.desc}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </div>
      )}

      {/* ─── Tab: Model Call Audit ─────────────────────────────────────────────── */}
      {tab === 'audit' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {/* Filter bar */}
          <div className="filter-bar" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Search by agent ID…"
              value={agentSearch}
              onChange={(e) => setAgentSearch(e.target.value)}
              style={{ width: '13rem' }}
            />
            <select
              value={auditProvider}
              onChange={(e) => { setAuditProvider(e.target.value); setAuditPage(1); }}
            >
              <option value="">All Providers</option>
              <option value="openai-codex">OpenAI Codex</option>
              <option value="anthropic-claude">Anthropic Claude</option>
              <option value="google-gemini">Google Gemini</option>
            </select>
            <select
              value={auditRisk}
              onChange={(e) => { setAuditRisk(e.target.value); setAuditPage(1); }}
            >
              <option value="">All Risk Levels</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
            {agentSearch && (
              <button className="btn-secondary" onClick={() => setAgentSearch('')} style={{ fontSize: '0.8125rem' }}>
                Clear
              </button>
            )}
          </div>

          <div className="table-card">
            <div className="table-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>Model Call Audit</span>
              <span style={{ fontSize: '0.8125rem', fontWeight: 400, color: '#64748b' }}>{auditTotal} records</span>
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
                <thead>
                  <tr style={{ background: '#0f172a', borderBottom: '1px solid #334155' }}>
                    {['Time', 'Agent', 'Provider', 'Risk', 'Strategy', 'Latency', 'Tokens', 'Redactions', 'Status'].map((h) => (
                      <th key={h} style={{ padding: '0.75rem 1rem', textAlign: h === 'Latency' || h === 'Tokens' ? 'right' : 'left', color: '#64748b', fontWeight: 600, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {displayedAudit.length === 0 && (
                    <tr>
                      <td colSpan={9} className="empty-state">
                        {agentSearch ? `No records matching "${agentSearch}"` : 'No records found'}
                      </td>
                    </tr>
                  )}
                  {displayedAudit.map((e, idx) => (
                    <tr key={e.call_id} style={{ borderTop: idx > 0 ? '1px solid #1e293b' : 'none' }}>
                      <td style={{ padding: '0.75rem 1rem', color: '#64748b', whiteSpace: 'nowrap' }}>
                        {new Date(e.timestamp).toLocaleString()}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', color: '#94a3b8' }}>{e.agent_id}</span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem', color: '#f1f5f9', fontWeight: 500 }}>
                        {e.provider === 'openai-codex' ? 'OpenAI Codex'
                          : e.provider === 'anthropic-claude' ? 'Claude'
                          : e.provider === 'google-gemini' ? 'Gemini'
                          : e.provider}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <RiskBadge level={e.risk_level} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <StrategyBadge strategy={e.routing_strategy} />
                      </td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right', color: '#94a3b8' }}>{e.latency_ms} ms</td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right', color: '#94a3b8' }}>{e.token_count.toLocaleString()}</td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        {(e.redactions ?? []).length > 0 ? (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                            {(e.redactions ?? []).map((r) => (
                              <span key={r} style={{ padding: '0.125rem 0.375rem', background: '#431407', border: '1px solid #ea580c', borderRadius: '4px', fontSize: '0.7rem', color: '#fb923c' }}>
                                {r.replace(/_/g, ' ')}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span style={{ color: '#334155' }}>—</span>
                        )}
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        {e.blocked ? (
                          <span style={{ display: 'inline-block', padding: '0.125rem 0.5rem', background: '#450a0a', border: '1px solid #dc2626', borderRadius: '9999px', color: '#f87171', fontSize: '0.75rem', fontWeight: 700 }}>Blocked</span>
                        ) : (
                          <span style={{ display: 'inline-block', padding: '0.125rem 0.5rem', background: '#052e16', border: '1px solid #16a34a', borderRadius: '9999px', color: '#4ade80', fontSize: '0.75rem', fontWeight: 700 }}>Passed</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {totalAuditPages > 1 && (
              <div style={{ padding: '0.75rem 1.25rem', borderTop: '1px solid #334155' }}>
                <Pagination page={auditPage} pageSize={PAGE_SIZE} total={auditTotal} onPageChange={setAuditPage} />
              </div>
            )}
          </div>
        </div>
      )}

      {/* ─── Tab: Guardrails ──────────────────────────────────────────────────── */}
      {tab === 'guardrails' && guardrails && (
        <GuardrailsPanel config={guardrails} onSave={handleGuardrailSave} />
      )}
      {tab === 'guardrails' && !guardrails && !loading && (
        <div className="card empty-state">
          Could not load guardrail configuration.
        </div>
      )}

      {/* ─── Tab: Configuration ───────────────────────────────────────────────── */}
      {tab === 'configuration' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* ModelGuard Config */}
          <div>
            <p className="section-title" style={{ marginBottom: '0.75rem' }}>ModelGuard Runtime Config</p>
            {mgConfig ? (
              <GuardrailsPanel config={mgConfig} onSave={handleMgConfigSave} />
            ) : policiesLoading ? (
              <div className="card loading-skeleton" style={{ height: '12rem' }} />
            ) : (
              <div className="card empty-state">Could not load ModelGuard configuration.</div>
            )}
          </div>

          {/* Baseline Policies */}
          <div>
            <p className="section-title" style={{ marginBottom: '0.75rem' }}>Baseline Policies</p>
            <PoliciesPanel
              policies={policies}
              loading={policiesLoading}
              onToggle={handlePolicyToggle}
              onSave={handlePolicySave}
              onDelete={handlePolicyDelete}
            />
          </div>
        </div>
      )}
    </div>
  );
}
