import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import type { HostStatsResponse, HostRule, Event } from '../api';
import { useInterval } from '../hooks/useInterval';
import Pagination from '../components/Pagination';

// ─── Constants ────────────────────────────────────────────────────────────────

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

const TIER_COLORS: Record<string, string> = {
  T0: '#334155',
  T1: '#1d4ed8',
  T2: '#d97706',
  T3: '#ea580c',
  T4: '#dc2626',
};

const TIER_BG: Record<string, string> = {
  T0: '#1e293b',
  T1: '#1e3a5f',
  T2: '#422006',
  T3: '#431407',
  T4: '#450a0a',
};

// ─── Severity badge ────────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const color = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.info;
  const bg    = SEVERITY_BG[severity]    ?? SEVERITY_BG.info;
  return (
    <span style={{ fontSize: '0.7rem', padding: '0.125rem 0.5rem', borderRadius: '9999px', background: bg, color, border: `1px solid ${color}40`, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
      {severity}
    </span>
  );
}

// ─── Tier badge ────────────────────────────────────────────────────────────────

function TierBadge({ tier }: { tier: number | string }) {
  const t = typeof tier === 'number' ? `T${tier}` : String(tier);
  const color = TIER_COLORS[t] ?? TIER_COLORS.T0;
  const bg    = TIER_BG[t]    ?? TIER_BG.T0;
  return (
    <span style={{ fontSize: '0.7rem', padding: '0.125rem 0.5rem', borderRadius: '9999px', background: bg, color, border: `1px solid ${color}40`, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
      {t}
    </span>
  );
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color }: { label: string; value: number | string; sub?: string; color?: string }) {
  return (
    <div className="card stat-card">
      <div className="stat-value" style={color ? { color } : undefined}>{value}</div>
      <div className="stat-label">{label}</div>
      {sub && <div style={{ fontSize: '0.7rem', color: '#334155', marginTop: '0.125rem' }}>{sub}</div>}
    </div>
  );
}

// ─── Threat bar ────────────────────────────────────────────────────────────────

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

// ─── Tier distribution bar ────────────────────────────────────────────────────

function TierDistribution({ breakdown }: { breakdown: Record<string, number> }) {
  const tiers = ['T0', 'T1', 'T2', 'T3', 'T4'];
  const total = tiers.reduce((s, t) => s + (breakdown[t] ?? 0), 0) || 1;
  return (
    <div>
      <div style={{ display: 'flex', borderRadius: '4px', overflow: 'hidden', height: '12px', marginBottom: '0.75rem', background: '#0f172a' }}>
        {tiers.map((t) => {
          const pct = ((breakdown[t] ?? 0) / total) * 100;
          return pct > 0 ? (
            <div key={t} style={{ width: `${pct}%`, background: TIER_COLORS[t] }} title={`${t}: ${breakdown[t] ?? 0}`} />
          ) : null;
        })}
      </div>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {tiers.map((t) => (
          <div key={t} style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: TIER_COLORS[t], display: 'inline-block' }} />
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
              {t}: <strong style={{ color: '#e2e8f0' }}>{breakdown[t] ?? 0}</strong>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Event type label helper ──────────────────────────────────────────────────

function eventTypeLabel(ev: Event): string {
  const meta = ev['metadata'] as Record<string, unknown> | undefined;
  if (meta) {
    const et = meta['event_type'];
    if (typeof et === 'string') return et;
  }
  return (ev['type'] as string | undefined) ?? '—';
}

function processName(ev: Event): string {
  const meta = ev['metadata'] as Record<string, unknown> | undefined;
  if (meta) {
    const pn = meta['process_name'];
    if (typeof pn === 'string') return pn;
  }
  return '—';
}

function processPid(ev: Event): string {
  const meta = ev['metadata'] as Record<string, unknown> | undefined;
  if (meta) {
    const pid = meta['pid'];
    if (pid !== undefined) return String(pid);
  }
  return '—';
}

function hostname(ev: Event): string {
  return (ev['source'] as string | undefined) ?? '—';
}

function indicators(ev: Event): string[] {
  const raw = ev['indicators'];
  if (Array.isArray(raw)) return raw as string[];
  return [];
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function HostGuard() {
  const [stats, setStats] = useState<HostStatsResponse | null>(null);
  const [rules, setRules] = useState<HostRule[]>([]);
  const [events, setEvents] = useState<Event[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'overview' | 'events' | 'rules'>('overview');

  // Events tab filters
  const [eventTypeFilter, setEventTypeFilter] = useState('');
  const [hostnameFilter, setHostnameFilter] = useState('');
  const [eventsPage, setEventsPage] = useState(1);
  const PAGE_SIZE = 25;

  // Rules tab search
  const [ruleSearch, setRuleSearch] = useState('');

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, rl] = await Promise.all([api.hostGuardStats(), api.hostGuardRules()]);
      setStats(s);
      setRules(rl.rules ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load HostGuard data');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadEvents = useCallback(async () => {
    setEventsLoading(true);
    try {
      const res = await api.hostGuardEvents(
        eventTypeFilter || undefined,
        hostnameFilter || undefined,
        eventsPage,
      );
      setEvents(res.events ?? []);
      setEventsTotal(res.total ?? 0);
    } catch {
      setEvents([]);
      setEventsTotal(0);
    } finally {
      setEventsLoading(false);
    }
  }, [eventTypeFilter, hostnameFilter, eventsPage]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  useEffect(() => {
    if (tab === 'events') void loadEvents();
  }, [tab, loadEvents]);

  useInterval(loadData, 20000);

  // ─── Filtered rules ─────────────────────────────────────────────────────────
  const filteredRules = rules.filter((r) => {
    if (!ruleSearch) return true;
    const q = ruleSearch.toLowerCase();
    return (
      r.name.toLowerCase().includes(q) ||
      r.id.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q) ||
      r.severity.toLowerCase().includes(q)
    );
  });

  // ─── Top event types ────────────────────────────────────────────────────────
  const topEventTypes = [...(stats?.event_types ?? [])]
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  // ─── Page count ─────────────────────────────────────────────────────────────
  // totalPages computed by Pagination component

  // ─── Render loading ─────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={{ padding: '2rem' }}>
        <div className="card-grid">
          {[0, 1, 2, 3].map(i => (
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
          <button onClick={() => void loadData()} style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', textDecoration: 'underline', fontWeight: 600 }}>Retry</button>
        </div>
      </div>
    );
  }

  return (
    <div>
      {/* ─── Header ─────────────────────────────────────────────────────────── */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h2>🖥️ HostGuard</h2>
          <p>Host-level threat detection — processes, network, persistence, and privilege escalation</p>
        </div>
        <button className="btn-secondary" onClick={() => void loadData()} disabled={loading}>
          {loading ? '…' : '↻ Refresh'}
        </button>
      </div>

      {/* ─── Stat strip ─────────────────────────────────────────────────────── */}
      <div className="card-grid">
        <StatCard label="Total Events" value={(stats?.total_events ?? 0).toLocaleString()} sub={`Last ${stats?.period ?? '24h'}`} />
        <StatCard label="Threat Events" value={(stats?.threat_events ?? 0).toLocaleString()} sub="Tier 2+" color={(stats?.threat_events ?? 0) > 0 ? '#f87171' : undefined} />
        <StatCard label="Unique Hosts" value={stats?.unique_hosts ?? 0} sub="Monitored endpoints" />
        <StatCard label="Active Rules" value={stats?.active_rules ?? 0} sub={`of ${rules.length} total`} />
      </div>

      {/* ─── Tabs ────────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1.5rem', borderBottom: '1px solid #334155' }}>
        {(['overview', 'events', 'rules'] as const).map(t => (
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
            {t === 'overview' ? 'Overview' : t === 'events' ? 'Events' : 'Detection Rules'}
          </button>
        ))}
      </div>

      {/* ─── Overview tab ────────────────────────────────────────────────────── */}
      {tab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
          <div className="card">
            <div className="section-title" style={{ marginBottom: '1rem' }}>Top Event Types</div>
            {topEventTypes.length > 0 ? (
              topEventTypes.map((item, idx) => (
                <ThreatBar
                  key={item.type}
                  label={item.type}
                  count={item.count}
                  max={topEventTypes[0]?.count ?? 1}
                  color={['#3b82f6','#06b6d4','#ea580c','#dc2626','#7c3aed','#d97706','#ec4899','#14b8a6'][idx % 8]}
                />
              ))
            ) : (
              <div className="empty-state">No event data</div>
            )}
          </div>

          <div className="card">
            <div className="section-title" style={{ marginBottom: '1rem' }}>Tier Distribution</div>
            {stats?.tier_breakdown ? (
              <TierDistribution breakdown={stats.tier_breakdown} />
            ) : (
              <div className="empty-state">No tier data</div>
            )}
          </div>

          <div className="card" style={{ gridColumn: 'span 2' }}>
            <div className="section-title" style={{ marginBottom: '1rem' }}>Detection Coverage</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '0.75rem' }}>
              {rules.map(rule => (
                <div key={rule.id} style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '8px', padding: '0.75rem', borderLeft: `3px solid ${SEVERITY_COLORS[rule.severity] ?? '#475569'}` }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.375rem' }}>
                    <TierBadge tier={rule.tier} />
                    <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: rule.enabled ? '#4ade80' : '#334155', display: 'inline-block' }} />
                  </div>
                  <p style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#e2e8f0', marginTop: '0.5rem', lineHeight: 1.3 }}>{rule.name}</p>
                  <div style={{ marginTop: '0.375rem' }}>
                    <SeverityBadge severity={rule.severity} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ─── Events tab ──────────────────────────────────────────────────────── */}
      {tab === 'events' && (
        <div>
          <div className="filter-bar" style={{ marginBottom: '1rem' }}>
            <input
              type="text"
              placeholder="Filter by event type…"
              value={eventTypeFilter}
              onChange={(e) => { setEventTypeFilter(e.target.value); setEventsPage(1); }}
            />
            <input
              type="text"
              placeholder="Filter by hostname…"
              value={hostnameFilter}
              onChange={(e) => { setHostnameFilter(e.target.value); setEventsPage(1); }}
            />
            <button className="btn-secondary" onClick={() => { setEventTypeFilter(''); setHostnameFilter(''); setEventsPage(1); }}>
              Clear
            </button>
          </div>

          <div className="table-card">
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.875rem' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #334155' }}>
                    {['Time', 'Hostname', 'Event Type', 'Process', 'PID', 'Tier', 'Indicators'].map(h => (
                      <th key={h} style={{ padding: '0.625rem 1rem', textAlign: 'left', fontSize: '0.75rem', fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {eventsLoading ? (
                    <tr><td colSpan={7} style={{ padding: '3rem', textAlign: 'center' }}>
                      <div style={{ width: '24px', height: '24px', border: '2px solid #3b82f6', borderTopColor: 'transparent', borderRadius: '50%', margin: '0 auto', animation: 'spin 0.8s linear infinite' }} />
                    </td></tr>
                  ) : events.length === 0 ? (
                    <tr><td colSpan={7} className="empty-state">No host events found</td></tr>
                  ) : events.map((ev, idx) => {
                    const ind = indicators(ev);
                    const tier = typeof ev['tier'] === 'number' ? ev['tier'] as number : 0;
                    return (
                      <tr key={(ev['id'] as string | undefined) ?? idx} style={{ borderBottom: '1px solid #1e293b' }}
                        onMouseEnter={e => (e.currentTarget.style.background = '#0f172a')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.75rem', color: '#64748b', whiteSpace: 'nowrap' }}>
                          {new Date((ev['timestamp'] as string | undefined) ?? '').toLocaleString()}
                        </td>
                        <td style={{ padding: '0.75rem 1rem', fontWeight: 600, color: '#f1f5f9' }}>{hostname(ev)}</td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <span style={{ fontFamily: 'monospace', fontSize: '0.75rem', background: '#0f172a', color: '#94a3b8', padding: '0.125rem 0.375rem', borderRadius: '4px', border: '1px solid #334155' }}>
                            {eventTypeLabel(ev)}
                          </span>
                        </td>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.75rem', color: '#94a3b8' }}>{processName(ev)}</td>
                        <td style={{ padding: '0.75rem 1rem', fontFamily: 'monospace', fontSize: '0.75rem', color: '#64748b' }}>{processPid(ev)}</td>
                        <td style={{ padding: '0.75rem 1rem' }}><TierBadge tier={tier} /></td>
                        <td style={{ padding: '0.75rem 1rem' }}>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                            {ind.slice(0, 3).map(tag => (
                              <span key={tag} style={{ fontSize: '0.7rem', background: '#1c0a0a', color: '#fca5a5', border: '1px solid #7f1d1d', borderRadius: '4px', padding: '0.125rem 0.375rem' }}>
                                {tag.replace(/_/g, ' ')}
                              </span>
                            ))}
                            {ind.length > 3 && <span style={{ fontSize: '0.75rem', color: '#64748b' }}>+{ind.length - 3} more</span>}
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

      {/* ─── Rules tab ───────────────────────────────────────────────────────── */}
      {tab === 'rules' && (
        <div>
          <div className="filter-bar" style={{ marginBottom: '1rem' }}>
            <input
              type="text"
              placeholder="Search rules by name, ID, or severity…"
              value={ruleSearch}
              onChange={(e) => setRuleSearch(e.target.value)}
              style={{ width: '100%', maxWidth: 'none' }}
            />
            {ruleSearch && (
              <button className="btn-secondary" onClick={() => setRuleSearch('')}>Clear</button>
            )}
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
                        <span style={{ fontSize: '1rem', fontWeight: 700, color: '#f1f5f9' }}>{rule.name}</span>
                        <code style={{ fontSize: '0.7rem', color: '#475569', background: '#0f172a', padding: '0.125rem 0.375rem', borderRadius: '4px', border: '1px solid #334155' }}>{rule.id}</code>
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
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.5rem', flexShrink: 0 }}>
                      <SeverityBadge severity={rule.severity} />
                      <TierBadge tier={rule.tier} />
                      <span style={{ fontSize: '0.75rem', fontWeight: 600, color: rule.enabled ? '#4ade80' : '#475569' }}>
                        {rule.enabled ? '● Enabled' : '○ Disabled'}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}








