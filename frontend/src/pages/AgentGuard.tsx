import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import type { AgentRecord, AgentStatsResponse, AgentRule } from '../api';
import { useInterval } from '../hooks/useInterval';
import Pagination from '../components/Pagination';

// ─── Constants ────────────────────────────────────────────────────────────────

const PAGE_SIZE = 25;

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#dc2626',
  high:     '#ea580c',
  medium:   '#d97706',
  low:      '#2563eb',
  info:     '#475569',
};

const SEVERITY_BG: Record<string, string> = {
  critical: '#450a0a',
  high:     '#431407',
  medium:   '#422006',
  low:      '#1e3a5f',
  info:     '#1e293b',
};

const EVENT_TYPE_COLORS: Record<string, string> = {
  prompt_injection:          '#dc2626',
  data_exfiltration:         '#ea580c',
  unapproved_tool_use:       '#d97706',
  self_policy_modification:  '#7c3aed',
  unsanctioned_outreach:     '#be185d',
  unknown:                   '#475569',
};

const AGENT_COLORS = [
  '#3b82f6', '#8b5cf6', '#06b6d4', '#10b981',
  '#f59e0b', '#ef4444', '#ec4899', '#14b8a6',
];

// ─── Severity badge ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info;
  const bg    = SEVERITY_BG[severity]    ?? SEVERITY_BG.info;
  return (
    <span
      style={{
        fontSize: '0.7rem',
        padding: '0.125rem 0.5rem',
        borderRadius: '9999px',
        background: bg,
        color,
        border: `1px solid ${color}40`,
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: '0.05em',
      }}
    >
      {severity}
    </span>
  );
}

// ─── Agent status badge ───────────────────────────────────────────────────────

function StatusBadge({ agent }: { agent: AgentRecord }) {
  if (agent.quarantined)
    return (
      <span style={{ fontSize: '0.7rem', padding: '0.125rem 0.5rem', borderRadius: '9999px', background: '#450a0a', color: '#f87171', border: '1px solid #7f1d1d', fontWeight: 700, textTransform: 'uppercase' as const }}>
        Quarantined
      </span>
    );
  if (agent.suspended)
    return (
      <span style={{ fontSize: '0.7rem', padding: '0.125rem 0.5rem', borderRadius: '9999px', background: '#422006', color: '#fcd34d', border: '1px solid #92400e', fontWeight: 700, textTransform: 'uppercase' as const }}>
        Suspended
      </span>
    );
  return (
    <span style={{ fontSize: '0.7rem', padding: '0.125rem 0.5rem', borderRadius: '9999px', background: '#14532d', color: '#86efac', border: '1px solid #166534', fontWeight: 700, textTransform: 'uppercase' as const }}>
      Active
    </span>
  );
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <div className="card stat-card">
      <div className="stat-value" style={color ? { color } : undefined}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

// ─── Agent detail modal ───────────────────────────────────────────────────────

function AgentDetailModal({ agent, onClose, onAction }: {
  agent: AgentRecord;
  onClose: () => void;
  onAction: (id: string, action: 'suspend' | 'unsuspend' | 'quarantine') => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const act = async (action: 'suspend' | 'unsuspend' | 'quarantine') => {
    setBusy(true);
    await onAction(agent.agent_id, action);
    setBusy(false);
    onClose();
  };

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50 }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '12px', width: '100%', maxWidth: '520px', padding: '1.5rem', maxHeight: '90vh', overflowY: 'auto' }}
      >
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <div>
            <h2 style={{ color: '#f1f5f9', fontWeight: 700, fontSize: '1.125rem', margin: 0 }}>{agent.agent_name}</h2>
            <code style={{ color: '#64748b', fontSize: '0.75rem' }}>{agent.agent_id}</code>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#64748b', fontSize: '1.25rem', cursor: 'pointer', lineHeight: 1 }}>&times;</button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '1.25rem' }}>
          <InfoRow label="Type" value={agent.agent_type} />
          <InfoRow label="Status" value={<StatusBadge agent={agent} />} />
          <InfoRow label="Token Quota" value={agent.token_quota === 0 ? 'Unlimited' : agent.token_quota.toLocaleString()} />
          <InfoRow label="Call Quota" value={agent.call_quota === 0 ? 'Unlimited' : agent.call_quota.toLocaleString()} />
          <InfoRow label="Actions" value={agent.action_count.toLocaleString()} />
          <InfoRow label="Threats" value={String(agent.threat_count)} />
          <div style={{ gridColumn: 'span 2' }}>
            <InfoRow label="Approved Tools" value={agent.approved_tools.join(', ') || '—'} />
          </div>
          <div style={{ gridColumn: 'span 2' }}>
            <InfoRow label="Approved Domains" value={agent.approved_domains.join(', ') || '—'} />
          </div>
          {agent.registered_at && (
            <InfoRow label="Registered" value={new Date(agent.registered_at).toLocaleString()} />
          )}
          {agent.last_activity_at && (
            <InfoRow label="Last Activity" value={new Date(agent.last_activity_at).toLocaleString()} />
          )}
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', paddingTop: '1rem', borderTop: '1px solid #334155' }}>
          {!agent.suspended && !agent.quarantined && (
            <button
              disabled={busy}
              onClick={() => act('suspend')}
              style={{ flex: 1, padding: '0.5rem', borderRadius: '6px', background: '#422006', color: '#fcd34d', border: '1px solid #92400e', fontSize: '0.875rem', fontWeight: 600, cursor: busy ? 'not-allowed' : 'pointer' }}
            >
              Suspend
            </button>
          )}
          {agent.suspended && !agent.quarantined && (
            <button
              disabled={busy}
              onClick={() => act('unsuspend')}
              style={{ flex: 1, padding: '0.5rem', borderRadius: '6px', background: '#14532d', color: '#86efac', border: '1px solid #166534', fontSize: '0.875rem', fontWeight: 600, cursor: busy ? 'not-allowed' : 'pointer' }}
            >
              Unsuspend
            </button>
          )}
          {!agent.quarantined && (
            <button
              disabled={busy}
              onClick={() => act('quarantine')}
              style={{ flex: 1, padding: '0.5rem', borderRadius: '6px', background: '#450a0a', color: '#f87171', border: '1px solid #7f1d1d', fontSize: '0.875rem', fontWeight: 600, cursor: busy ? 'not-allowed' : 'pointer' }}
            >
              Quarantine
            </button>
          )}
          <button
            onClick={onClose}
            style={{ flex: 1, padding: '0.5rem', borderRadius: '6px', background: '#0f172a', color: '#94a3b8', border: '1px solid #334155', fontSize: '0.875rem', fontWeight: 600, cursor: 'pointer' }}
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <p style={{ fontSize: '0.7rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', margin: '0 0 0.25rem' }}>{label}</p>
      <div style={{ fontSize: '0.875rem', color: '#e2e8f0', fontWeight: 500 }}>{value}</div>
    </div>
  );
}

// ─── Threat bar ───────────────────────────────────────────────────────────────

function ThreatBar({ label, count, max, color }: { label: string; count: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((count / max) * 100) : 0;
  return (
    <div style={{ marginBottom: '0.625rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
        <span style={{ color: '#cbd5e1', textTransform: 'capitalize' }}>{label.replace(/_/g, ' ')}</span>
        <span style={{ color: '#94a3b8' }}>{count}</span>
      </div>
      <div style={{ background: '#0f172a', borderRadius: '4px', height: '8px', overflow: 'hidden' }}>
        <div style={{ height: '100%', borderRadius: '4px', width: `${pct}%`, background: color, transition: 'width 0.5s ease' }} />
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function AgentGuard() {
  const [stats, setStats] = useState<AgentStatsResponse | null>(null);
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [rules, setRules] = useState<AgentRule[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<AgentRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'agents' | 'events' | 'rules'>('agents');
  const [events, setEvents] = useState<Record<string, unknown>[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [agentFilter, setAgentFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [eventsPage, setEventsPage] = useState(1);
  const [agentSearch, setAgentSearch] = useState('');
  const [ruleSearch, setRuleSearch] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, al, rl] = await Promise.all([
        api.agentStats(),
        api.agentList(),
        api.agentRules(),
      ]);
      setStats(s);
      setAgents(al.agents ?? []);
      setRules(rl.rules ?? []);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadEvents = useCallback(async () => {
    try {
      const res = await api.agentEvents(agentFilter || undefined, typeFilter || undefined, eventsPage);
      setEvents(res.events ?? []);
      setEventsTotal(res.total ?? 0);
    } catch {
      setEvents([]);
    }
  }, [agentFilter, typeFilter, eventsPage]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { if (tab === 'events') void loadEvents(); }, [tab, loadEvents]);
  useInterval(load, 20000);

  const maxEventTypeCount = (stats?.event_types ?? []).reduce((m, e) => Math.max(m, e.count), 1);

  const handleAction = async (id: string, action: 'suspend' | 'unsuspend' | 'quarantine') => {
    if (action === 'suspend') await api.suspendAgent(id);
    else if (action === 'unsuspend') await api.unsuspendAgent(id);
    else await api.quarantineAgent(id);
    await load();
  };

  const activeAgents = agents.filter(a => !a.suspended && !a.quarantined);
  const suspendedAgents = agents.filter(a => a.suspended);
  const quarantinedAgents = agents.filter(a => a.quarantined);

  const filteredAgents = agents.filter(a => {
    if (!agentSearch) return true;
    const q = agentSearch.toLowerCase();
    return (
      a.agent_name.toLowerCase().includes(q) ||
      a.agent_id.toLowerCase().includes(q) ||
      a.agent_type.toLowerCase().includes(q)
    );
  });

  const filteredRules = rules.filter(r => {
    if (!ruleSearch) return true;
    const q = ruleSearch.toLowerCase();
    return (
      r.name.toLowerCase().includes(q) ||
      r.id.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q) ||
      r.severity.toLowerCase().includes(q)
    );
  });

  if (loading && agents.length === 0) {
    return (
      <div style={{ padding: '2rem' }}>
        <div className="card-grid">
          {[0, 1, 2, 3, 4, 5].map(i => (
            <div key={i} className="loading-skeleton" style={{ height: '5rem', borderRadius: '8px' }} />
          ))}
        </div>
        <div className="loading-skeleton" style={{ height: '16rem', borderRadius: '8px', marginTop: '1rem' }} />
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: '2rem' }}>
        <div className="error-msg" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>⚠️ {error}</span>
          <button onClick={() => void load()} style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', textDecoration: 'underline', fontWeight: 600 }}>Retry</button>
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* ── Page Header ─────────────────────────────────────────────────── */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h2>🤖 AgentGuard</h2>
          <p>AI agent policy enforcement and threat detection</p>
        </div>
        <button className="btn-secondary" onClick={() => void load()} disabled={loading}>
          {loading ? '…' : '↻ Refresh'}
        </button>
      </div>

      {/* ── Stats Row ────────────────────────────────────────────────────── */}
      <div className="card-grid">
        <StatCard label="Total Agents" value={stats?.total_agents ?? agents.length} />
        <StatCard label="Active" value={stats?.active_agents ?? activeAgents.length} color="#86efac" />
        <StatCard label="Suspended" value={stats?.suspended_count ?? suspendedAgents.length} color={(stats?.suspended_count ?? suspendedAgents.length) > 0 ? '#fcd34d' : undefined} />
        <StatCard label="Quarantined" value={stats?.quarantine_count ?? quarantinedAgents.length} color={(stats?.quarantine_count ?? quarantinedAgents.length) > 0 ? '#f87171' : undefined} />
        <StatCard label="Total Threats" value={stats?.total_threats ?? 0} color={(stats?.total_threats ?? 0) > 0 ? '#f87171' : undefined} />
        <StatCard label="Total Actions" value={(stats?.total_actions ?? 0).toLocaleString()} />
      </div>

      {/* ── Tabs ─────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1.5rem', borderBottom: '1px solid #334155' }}>
        {(['agents', 'events', 'rules'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: '0.625rem 1.25rem',
              background: 'none',
              border: 'none',
              borderBottom: `2px solid ${tab === t ? '#3b82f6' : 'transparent'}`,
              color: tab === t ? '#60a5fa' : '#64748b',
              fontWeight: 600,
              fontSize: '0.875rem',
              cursor: 'pointer',
              transition: 'color 0.12s, border-color 0.12s',
              marginBottom: '-1px',
            }}
          >
            {t === 'agents' ? 'Agent Registry' : t === 'events' ? 'Threat Events' : 'Detection Rules'}
          </button>
        ))}
      </div>

      {/* ── Tab: Agent Registry ── */}
      {tab === 'agents' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: '1.25rem', alignItems: 'start' }}>
          <div className="table-card">
            <div className="table-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span>Registered Agents</span>
              <input
                type="text"
                placeholder="Search agents…"
                value={agentSearch}
                onChange={e => setAgentSearch(e.target.value)}
                style={{ background: '#0f172a', border: '1px solid #334155', color: '#e2e8f0', borderRadius: '6px', padding: '0.25rem 0.75rem', fontSize: '0.8125rem', outline: 'none', width: '180px' }}
              />
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #334155' }}>
                    {['Agent', 'Type', 'Status', 'Actions', 'Threats', ''].map(h => (
                      <th key={h} style={{ padding: '0.625rem 1rem', textAlign: h === 'Actions' || h === 'Threats' ? 'right' : 'left', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredAgents.length === 0 ? (
                    <tr><td colSpan={6} className="empty-state">No agents registered</td></tr>
                  ) : filteredAgents.map((agent, idx) => (
                    <tr key={agent.agent_id} style={{ borderBottom: '1px solid #1e293b' }}
                      onMouseEnter={e => (e.currentTarget.style.background = '#0f172a')}
                      onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: AGENT_COLORS[idx % AGENT_COLORS.length], flexShrink: 0 }} />
                          <div>
                            <div style={{ fontWeight: 600, color: '#f1f5f9' }}>{agent.agent_name}</div>
                            <div style={{ fontSize: '0.7rem', color: '#475569', fontFamily: 'monospace' }}>{agent.agent_id}</div>
                          </div>
                        </div>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}>
                        <span style={{ fontSize: '0.75rem', padding: '0.125rem 0.5rem', borderRadius: '4px', background: '#0f172a', color: '#94a3b8', border: '1px solid #334155' }}>{agent.agent_type}</span>
                      </td>
                      <td style={{ padding: '0.75rem 1rem' }}><StatusBadge agent={agent} /></td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right', color: '#94a3b8' }}>{agent.action_count.toLocaleString()}</td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right', color: agent.threat_count > 0 ? '#f87171' : '#475569', fontWeight: agent.threat_count > 0 ? 700 : 400 }}>{agent.threat_count}</td>
                      <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                        <button onClick={() => setSelectedAgent(agent)} style={{ fontSize: '0.75rem', color: '#60a5fa', background: 'none', border: 'none', cursor: 'pointer', fontWeight: 600 }}>Details</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
                </table>
              </div>
          </div>

          <div className="card">
            <div className="section-title" style={{ marginBottom: '1rem' }}>Threat Breakdown</div>
            {stats?.event_types && stats.event_types.length > 0 ? (
              stats.event_types.map(et => (
                <ThreatBar
                  key={et.type}
                  label={et.type}
                  count={et.count}
                  max={maxEventTypeCount}
                  color={EVENT_TYPE_COLORS[et.type] ?? '#475569'}
                />
              ))
            ) : (
              <div className="empty-state">No threat data</div>
            )}
          </div>
        </div>
      )}

      {/* ── Tab: Threat Events ── */}
      {tab === 'events' && (
        <div>
          <div className="filter-bar" style={{ marginBottom: '1rem' }}>
            <input
              type="text"
              placeholder="Filter by agent ID…"
              value={agentFilter}
              onChange={e => { setAgentFilter(e.target.value); setEventsPage(1); }}
            />
            <input
              type="text"
              placeholder="Filter by event type…"
              value={typeFilter}
              onChange={e => { setTypeFilter(e.target.value); setEventsPage(1); }}
            />
            <button className="btn-secondary" onClick={() => void loadEvents()}>Search</button>
          </div>
          <div className="table-card">
            <div className="table-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span>Agent Threat Events</span>
              <span style={{ fontSize: '0.8125rem', color: '#64748b' }}>{eventsTotal} events</span>
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #334155' }}>
                    {['Time', 'Agent', 'Event Type', 'Severity', 'Indicators'].map(h => (
                      <th key={h} style={{ padding: '0.625rem 1rem', textAlign: 'left', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {events.length === 0 ? (
                    <tr><td colSpan={5} className="empty-state">No threat events found</td></tr>
                  ) : events.map((ev, i) => {
                    const meta = (ev.metadata as Record<string, unknown>) ?? {};
                    const indicators = (ev.indicators as string[]) ?? [];
                    const evType = String(meta.event_type ?? ev.event_type ?? '');
                    return (
                      <tr key={(ev.event_id as string) ?? i} style={{ borderBottom: '1px solid #1e293b' }}
                        onMouseEnter={e => (e.currentTarget.style.background = '#0f172a')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                        <td style={{ padding: '0.75rem 1rem', fontSize: '0.75rem', color: '#64748b', whiteSpace: 'nowrap' }}>
                          {ev.timestamp ? new Date(ev.timestamp as string).toLocaleString() : '—'}
                        </td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <div style={{ fontWeight: 600, color: '#f1f5f9' }}>{String(meta.agent_name ?? '—')}</div>
                          <div style={{ fontSize: '0.7rem', color: '#475569', fontFamily: 'monospace' }}>{String(meta.agent_id ?? '')}</div>
                        </td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <span style={{ color: EVENT_TYPE_COLORS[evType] ?? '#94a3b8', textTransform: 'capitalize' }}>
                            {evType.replace(/_/g, ' ') || '—'}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <SeverityBadge severity={String(ev.severity ?? 'info')} />
                        </td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                            {indicators.slice(0, 3).map(ind => (
                              <span key={ind} style={{ fontSize: '0.7rem', padding: '0.125rem 0.375rem', borderRadius: '4px', background: '#1c0a0a', color: '#fca5a5', border: '1px solid #7f1d1d' }}>
                                {ind.replace(/_/g, ' ')}
                              </span>
                            ))}
                            {indicators.length > 3 && (
                              <span style={{ fontSize: '0.75rem', color: '#64748b' }}>+{indicators.length - 3} more</span>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {eventsTotal > PAGE_SIZE && (
              <div style={{ padding: '0.75rem 1.25rem', borderTop: '1px solid #334155' }}>
                <Pagination page={eventsPage} pageSize={PAGE_SIZE} total={eventsTotal} onPageChange={setEventsPage} />
              </div>
            )}
          </div>
        </div>
      )}

      {tab === 'rules' && (
        <div>
          <div className="filter-bar" style={{ marginBottom: '1rem' }}>
            <input
              type="text"
              placeholder="Search rules by name, ID, or severity…"
              value={ruleSearch}
              onChange={e => setRuleSearch(e.target.value)}
              style={{ width: '100%', maxWidth: 'none' }}
            />
          </div>
          {filteredRules.length === 0 ? (
            <div className="card empty-state">No rules match your search</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {filteredRules.map(rule => (
                <div key={rule.id} className="card" style={{ borderLeft: `3px solid ${SEVERITY_COLORS[rule.severity] ?? '#475569'}` }}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem', flexWrap: 'wrap' }}>
                        <code style={{ fontSize: '0.7rem', color: '#475569', background: '#0f172a', padding: '0.125rem 0.375rem', borderRadius: '4px', border: '1px solid #334155' }}>{rule.id}</code>
                        <span style={{ fontSize: '1rem', fontWeight: 700, color: '#f1f5f9' }}>{rule.name}</span>
                        <SeverityBadge severity={rule.severity} />
                        <span style={{ fontSize: '0.7rem', color: '#64748b', background: '#0f172a', padding: '0.125rem 0.375rem', borderRadius: '4px', border: '1px solid #334155' }}>Tier {rule.tier}</span>
                      </div>
                      <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '0.625rem' }}>{rule.description}</p>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
                        {rule.responses.map(r => (
                          <span key={r} style={{ fontSize: '0.7rem', padding: '0.125rem 0.5rem', borderRadius: '4px', background: '#1e3a5f', color: '#93c5fd', border: '1px solid #1d4ed8' }}>
                            {r.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                    <span style={{ fontSize: '0.75rem', padding: '0.25rem 0.625rem', borderRadius: '6px', fontWeight: 600, flexShrink: 0, ...(rule.enabled ? { background: '#14532d', color: '#86efac', border: '1px solid #166534' } : { background: '#1e293b', color: '#475569', border: '1px solid #334155' }) }}>
                      {rule.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Agent detail modal */}
      {selectedAgent && (
        <AgentDetailModal
          agent={selectedAgent}
          onClose={() => setSelectedAgent(null)}
          onAction={handleAction}
        />
      )}
    </div>
  );
}
