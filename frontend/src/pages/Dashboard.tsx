import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, type HealthResponse, type EventsResponse, type IncidentsResponse, type Event, type SystemStats, type SummaryResponse, type HostStatsResponse, type AgentStatsResponse, type ModelGuardStatsResponse, type CommsStatsResponse, type NetStatsResponse } from '../api';
import { useInterval } from '../hooks/useInterval';
import { useSSE } from '../hooks/useSSE';
import MiniBarChart from '../components/MiniBarChart';
import CPUGauge from '../components/CPUGauge';
import AISummary from '../components/AISummary';

const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? '';

const TIER_COLORS: Record<number, string> = {
  0: '#334155',
  1: '#1d4ed8',
  2: '#d97706',
  3: '#ea580c',
  4: '#dc2626',
};

const RISK_BANDS = [
  { label: '0–25', min: 0, max: 25, color: '#16a34a' },
  { label: '26–50', min: 26, max: 50, color: '#d97706' },
  { label: '51–75', min: 51, max: 75, color: '#ea580c' },
  { label: '76–100', min: 76, max: 100, color: '#dc2626' },
];

export default function Dashboard() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [events, setEvents] = useState<EventsResponse | null>(null);
  const [incidents, setIncidents] = useState<IncidentsResponse | null>(null);
  const [sysStats, setSysStats] = useState<SystemStats | null>(null);
  const [aiSummary, setAiSummary] = useState<SummaryResponse | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [summaryError, setSummaryError] = useState('');
  const [error, setError] = useState('');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [liveCount, setLiveCount] = useState(0);
  const [hostStats, setHostStats] = useState<HostStatsResponse | null>(null);
  const [agentStats, setAgentStats] = useState<AgentStatsResponse | null>(null);
  const [modelStats, setModelStats] = useState<ModelGuardStatsResponse | null>(null);
  const [commsStats, setCommsStats] = useState<CommsStatsResponse | null>(null);
  const [netStats, setNetStats] = useState<NetStatsResponse | null>(null);

  const fetchSummary = useCallback((
    evts: EventsResponse | null,
    incs: IncidentsResponse | null,
    stats: SystemStats | null,
    hStats: HostStatsResponse | null,
    aStats: AgentStatsResponse | null,
    mStats: ModelGuardStatsResponse | null,
    cStats: CommsStatsResponse | null,
    force = false,
  ) => {
    // Aggregate event-type counts from the current event window
    const typeMap: Record<string, number> = {};
    const tierMap: Record<string, number> = {};
    const statusMap: Record<string, number> = {};

    for (const ev of evts?.events ?? []) {
      const t = (ev as { metadata?: { event_type?: string } }).metadata?.event_type ?? ev.type ?? 'unknown';
      typeMap[t] = (typeMap[t] ?? 0) + 1;
      const tier = `T${ev.tier ?? 0}`;
      tierMap[tier] = (tierMap[tier] ?? 0) + 1;
    }
    for (const inc of incs?.incidents ?? []) {
      const s = inc.status ?? 'unknown';
      statusMap[s] = (statusMap[s] ?? 0) + 1;
    }

    if (!force && aiSummary) return;   // skip if we already have one (cache is server-side)

    setSummaryLoading(true);
    setSummaryError('');
    api.summary({
      total_events: evts?.total ?? 0,
      total_incidents: incs?.total ?? 0,
      cpu_util_pct: stats?.cpu_util_pct ?? -1,
      mem_used_pct: stats?.mem_used_pct ?? 0,
      load_avg_1m: stats?.load_avg_1m ?? 0,
      top_event_types: Object.entries(typeMap)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([type, count]) => ({ type, count })),
      tier_breakdown: Object.entries(tierMap).map(([tier, count]) => ({ tier, count })),
      incident_statuses: Object.entries(statusMap).map(([status, count]) => ({ status, count })),
      // HostGuard
      host_total_events:  hStats?.total_events  ?? 0,
      host_threat_events: hStats?.threat_events ?? 0,
      host_unique_hosts:  hStats?.unique_hosts  ?? 0,
      host_active_rules:  hStats?.active_rules  ?? 0,
      // AgentGuard
      agent_total_agents:    aStats?.total_agents     ?? 0,
      agent_active_agents:   aStats?.active_agents    ?? 0,
      agent_suspended_count: aStats?.suspended_count  ?? 0,
      agent_quarantine_count: aStats?.quarantine_count ?? 0,
      agent_total_threats:   aStats?.total_threats    ?? 0,
      // ModelGuard
      model_total_calls:    mStats?.total_calls    ?? 0,
      model_blocked_calls:  mStats?.blocked_calls  ?? 0,
      model_avg_latency_ms: mStats?.avg_latency_ms ?? 0,
      model_avg_confidence: mStats?.avg_confidence ?? 0,
      model_risk_breakdown: mStats?.risk_breakdown ?? [],
      // CommsGuard
      comms_total_events:    cStats?.total_events ?? 0,
      comms_total_threats:   cStats?.total_threats ?? 0,
      comms_top_event_types: cStats?.event_types?.slice(0, 5) ?? [],
      // Threat / anomaly breakdowns
      host_top_event_types:  hStats?.event_types?.slice(0, 5) ?? [],
      agent_top_event_types: aStats?.event_types?.slice(0, 5) ?? [],
    })
      .then((r) => setAiSummary(r))
      .catch((err: unknown) => setSummaryError(
        err instanceof Error ? err.message : 'Could not reach AI provider — set an API key in Model Settings.',
      ))
      .finally(() => setSummaryLoading(false));
  }, [aiSummary]);

  const fetchAll = useCallback(() => {
    // Guard module stats — fire-and-forget so they don't block the main load
    api.hostGuardStats().then(setHostStats).catch(() => {});
    api.agentStats().then(setAgentStats).catch(() => {});
    api.modelGuardStats().then(setModelStats).catch(() => {});
    api.commsStats().then(setCommsStats).catch(() => {});
    api.networkGuardStats().then(setNetStats).catch(() => {});

    Promise.all([api.health(), api.events(), api.incidents(), api.systemStats()])
      .then(([h, e, i, s]) => {
        setHealth(h);
        setEvents(e);
        setIncidents(i);
        setSysStats(s);
        setLastUpdated(new Date());
        // Fetch summary once after first data load (skip on subsequent polls
        // unless the user explicitly triggers regeneration).
        fetchSummary(e, i, s, hostStats, agentStats, modelStats, commsStats, false);
      })
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      );
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);
  // Keep a REST polling fallback at 5 s in case the SSE connection drops.
  useInterval(fetchAll, 5000);
  // Auto-regenerate the AI summary every 5 minutes.
  useInterval(
    () => fetchSummary(events, incidents, sysStats, hostStats, agentStats, modelStats, commsStats, true),
    5 * 60 * 1000,
  );

  // Build the SSE URL, passing the JWT as a query param (EventSource can't
  // send custom headers, so the backend accepts ?token= as a fallback).
  const token = localStorage.getItem('og_token') ?? '';
  const sseUrl = useMemo(
    () => (token ? `${BASE}/api/v1/events/stream?token=${encodeURIComponent(token)}` : null),
    [token],
  );

  // Handle live events pushed over SSE — prepend to the current list so they
  // show up immediately without waiting for the next poll cycle.
  const handleLiveEvent = useCallback((data: unknown) => {
    const event = data as Event;
    setEvents((prev) => {
      if (!prev) return prev;
      // Deduplicate by id in case the REST poll also returns the same event.
      const exists = prev.events.some((e) => e.id && e.id === event.id);
      if (exists) return prev;
      return {
        ...prev,
        events: [event, ...prev.events],
        total: prev.total + 1,
      };
    });
    setLastUpdated(new Date());
    setLiveCount((n) => n + 1);
  }, []);

  useSSE(sseUrl, handleLiveEvent);

  const tierCounts = [0, 1, 2, 3, 4].map((tier) => ({
    tier,
    count: events?.events.filter((e) => e.tier === tier).length ?? 0,
  }));
  const totalEvents = events?.events.length ?? 0;

  const riskCounts = RISK_BANDS.map((band) => ({
    ...band,
    count: events?.events.filter((e) => {
      const s = e.risk_score as number | undefined;
      return s !== undefined && s >= band.min && s <= band.max;
    }).length ?? 0,
  }));

  return (
    <div>
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h2>Dashboard</h2>
          <p>OpenGuard v5 — Security Operations Overview</p>
          {lastUpdated && (
            <p style={{ fontSize: '0.75rem', color: '#475569', marginTop: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              Last updated: {lastUpdated.toLocaleTimeString()}
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: '0.25rem',
                fontSize: '0.7rem', fontWeight: 600, color: '#16a34a',
                border: '1px solid #16a34a', borderRadius: '4px', padding: '1px 6px',
              }}>
                <span style={{
                  width: '6px', height: '6px', borderRadius: '50%',
                  background: '#16a34a', animation: 'pulse 2s infinite',
                }} />
                LIVE{liveCount > 0 ? ` +${liveCount}` : ''}
              </span>
            </p>
          )}
        </div>
        <button className="btn-secondary" onClick={fetchAll}>↻ Refresh</button>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      <div className="card-grid">
        <div className="card stat-card">
          <div className="stat-value">
            {health ? (
              <span className={`badge badge-${health.status === 'ok' ? 'ok' : 'error'}`}>
                {health.status}
              </span>
            ) : (
              '—'
            )}
          </div>
          <div className="stat-label">System Health</div>
        </div>

        <div className="card stat-card">
          <div className="stat-value">{events ? events.total : '—'}</div>
          <div className="stat-label">Total Events</div>
        </div>

        <div className="card stat-card">
          <div className="stat-value">{incidents ? incidents.total : '—'}</div>
          <div className="stat-label">Active Incidents</div>
        </div>

        <div className="card stat-card">
          <div className="stat-value">
            {health ? health.version : '—'}
          </div>
          <div className="stat-label">Platform Version</div>
        </div>
      </div>

      {/* ── Security Modules Overview ───────────────────────────────── */}
      <div className="card-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))' }}>
        {/* HostGuard */}
        <div className="card" style={{ borderLeft: '3px solid #ea580c', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.9375rem' }}>🖥️ HostGuard</span>
            <Link to="/hostguard" style={{ fontSize: '0.8125rem', color: '#94a3b8', textDecoration: 'none' }}>View →</Link>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9' }}>{hostStats?.total_events ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Total Events</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#ea580c' }}>{hostStats?.threat_events ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Threat Events</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9' }}>{hostStats?.unique_hosts ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Unique Hosts</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9' }}>{hostStats?.active_rules ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Active Rules</div>
            </div>
          </div>
        </div>

        {/* AgentGuard */}
        <div className="card" style={{ borderLeft: '3px solid #7c3aed', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.9375rem' }}>🤖 AgentGuard</span>
            <Link to="/agentguard" style={{ fontSize: '0.8125rem', color: '#94a3b8', textDecoration: 'none' }}>View →</Link>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#4ade80' }}>{agentStats?.active_agents ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Active Agents</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#ea580c' }}>{agentStats?.quarantine_count ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Quarantined</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#d97706' }}>{agentStats?.suspended_count ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Suspended</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#dc2626' }}>{agentStats?.total_threats ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Total Threats</div>
            </div>
          </div>
        </div>

        {/* ModelGuard */}
        <div className="card" style={{ borderLeft: '3px solid #2563eb', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.9375rem' }}>🧠 ModelGuard</span>
            <Link to="/modelguard" style={{ fontSize: '0.8125rem', color: '#94a3b8', textDecoration: 'none' }}>View →</Link>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9' }}>{modelStats?.total_calls ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Total Calls</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#dc2626' }}>{modelStats?.blocked_calls ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Blocked</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9' }}>{modelStats ? `${modelStats.avg_latency_ms} ms` : '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Avg Latency</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#4ade80' }}>{modelStats ? `${((modelStats.avg_confidence ?? 0) * 100).toFixed(0)}%` : '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Avg Confidence</div>
            </div>
          </div>
        </div>

        {/* NetworkGuard */}
        <div className="card" style={{ borderLeft: '3px solid #22c55e', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.9375rem' }}>🌐 NetworkGuard</span>
            <Link to="/networkguard" style={{ fontSize: '0.8125rem', color: '#94a3b8', textDecoration: 'none' }}>View →</Link>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9' }}>{netStats?.total_events ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Total Events</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f87171' }}>{netStats?.threat_events ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Threat Events</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f1f5f9' }}>{netStats?.unique_sources ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Unique Sources</div>
            </div>
            <div>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#fb923c' }}>{netStats?.blocked_flows ?? '—'}</div>
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>Blocked Flows</div>
            </div>
          </div>
        </div>
      </div>

      {/* ── AI Summary ───────────────────────────────────────────────── */}
      <AISummary
        data={aiSummary}
        loading={summaryLoading}
        error={summaryError}
        onRefresh={() => fetchSummary(events, incidents, sysStats, hostStats, agentStats, modelStats, commsStats, true)}
      />

      {/* ── CPU & Memory utilisation row ─────────────────────────────── */}
      <div className="card-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))' }}>
        {/* CPU utilisation gauge */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
          <div className="section-title" style={{ alignSelf: 'flex-start', marginBottom: '0.25rem' }}>CPU Utilisation Rate</div>
          <CPUGauge utilPct={sysStats ? sysStats.cpu_util_pct : -1} size={130} />
          <div style={{ display: 'flex', gap: '1.25rem', fontSize: '0.75rem', color: '#94a3b8', marginTop: '0.25rem' }}>
            <span><span style={{ color: '#64748b' }}>Cores </span>{sysStats ? sysStats.cpu_cores : '—'}</span>
            <span><span style={{ color: '#64748b' }}>Load 1m </span>{sysStats ? sysStats.load_avg_1m.toFixed(2) : '—'}</span>
            <span><span style={{ color: '#64748b' }}>5m </span>{sysStats ? sysStats.load_avg_5m.toFixed(2) : '—'}</span>
            <span><span style={{ color: '#64748b' }}>15m </span>{sysStats ? sysStats.load_avg_15m.toFixed(2) : '—'}</span>
          </div>
        </div>

        {/* Memory utilisation bar */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: '0.75rem' }}>
          <div className="section-title">Memory Utilisation</div>
          {sysStats && sysStats.mem_total_mb > 0 ? (() => {
            const APP_COLORS = ['#3b82f6','#8b5cf6','#ec4899','#f59e0b','#06b6d4','#10b981','#f97316'];
            const usedPct  = Math.min(100, sysStats.mem_used_pct);
            const apps = sysStats.mem_apps ?? [];
            // Build segmented bar from per-app RSS; remainder shown as free
            const totalMB = sysStats.mem_total_mb;
            const appTotal = apps.reduce((s, a) => s + a.mem_mb, 0);
            const freeMB = Math.max(0, totalMB - appTotal);
            const segments = [
              ...apps.map((a, i) => ({
                label: a.name,
                mb: a.mem_mb,
                pct: (a.mem_mb / totalMB) * 100,
                color: a.name === 'Other' ? '#374151' : APP_COLORS[i % APP_COLORS.length],
              })),
              { label: 'Free', mb: freeMB, pct: (freeMB / totalMB) * 100, color: '#1e3a5f' },
            ];
            return (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem', color: '#f1f5f9', fontWeight: 600 }}>
                  <span>{usedPct.toFixed(1)}% used</span>
                  <span style={{ color: '#64748b', fontWeight: 400 }}>
                    {(sysStats.mem_used_mb / 1024).toFixed(1)} GB / {(totalMB / 1024).toFixed(1)} GB
                  </span>
                </div>
                {/* Per-app segmented distribution bar */}
                <div style={{ display: 'flex', borderRadius: '6px', overflow: 'hidden', height: '14px', background: '#0f172a' }}>
                  {segments.map(seg => seg.pct > 0.2 && (
                    <div
                      key={seg.label}
                      style={{ width: `${seg.pct}%`, background: seg.color, transition: 'width 0.6s ease' }}
                      title={`${seg.label}: ${seg.mb.toFixed(0)} MB (${seg.pct.toFixed(1)}%)`}
                    />
                  ))}
                </div>
                {/* Legend */}
                <div style={{ display: 'flex', gap: '0.75rem 1.25rem', flexWrap: 'wrap' }}>
                  {segments.filter(s => s.pct > 0.2).map(seg => (
                    <div key={seg.label} style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                      <span style={{ width: '9px', height: '9px', borderRadius: '50%', background: seg.color, display: 'inline-block', flexShrink: 0 }} />
                      <span style={{ fontSize: '0.73rem', color: '#94a3b8' }}>
                        {seg.label}
                        <strong style={{ color: '#e2e8f0' }}> {seg.mb.toFixed(0)} MB</strong>
                        <span style={{ color: '#475569' }}> · {seg.pct.toFixed(1)}%</span>
                      </span>
                    </div>
                  ))}
                </div>
              </>
            );
          })() : (
            <div style={{ color: '#475569', fontSize: '0.875rem' }}>Awaiting first sample…</div>
          )}
        </div>
      </div>

      {events && (
        <div className="card-grid">
          <div className="card">
            <div className="section-title">Tier Breakdown</div>
            {tierCounts.map(({ tier, count }) => (
              <MiniBarChart
                key={tier}
                label={`T${tier}`}
                value={count}
                max={totalEvents}
                color={TIER_COLORS[tier]}
              />
            ))}
          </div>

          <div className="card">
            <div className="section-title">Risk Score Distribution</div>
            {riskCounts.map((band) => (
              <MiniBarChart
                key={band.label}
                label={band.label}
                value={band.count}
                max={totalEvents}
                color={band.color}
              />
            ))}
          </div>
        </div>
      )}

      <div className="card-grid">
        <div className="table-card">
          <div className="table-header">
            Recent Events &nbsp;
            <Link to="/events" style={{ fontSize: '0.8125rem', fontWeight: 400 }}>
              View all →
            </Link>
          </div>
          {!events ? (
            <div className="loading">Loading…</div>
          ) : events.events.length === 0 ? (
            <div className="empty-state">No events recorded yet.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Type</th>
                  <th>Tier</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {events.events.slice(0, 5).map((ev, i) => (
                  <tr key={ev.id ?? i}>
                    <td>{ev.id ?? '—'}</td>
                    <td>{ev.type ?? '—'}</td>
                    <td>
                      {ev.tier !== undefined ? (
                        <span className={`badge badge-t${ev.tier}`}>T{ev.tier}</span>
                      ) : '—'}
                    </td>
                    <td>{ev.timestamp ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="table-card">
          <div className="table-header">
            Active Incidents &nbsp;
            <Link to="/incidents" style={{ fontSize: '0.8125rem', fontWeight: 400 }}>
              View all →
            </Link>
          </div>
          {!incidents ? (
            <div className="loading">Loading…</div>
          ) : incidents.incidents.length === 0 ? (
            <div className="empty-state">No active incidents.</div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Tier</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {incidents.incidents.slice(0, 5).map((inc, i) => (
                  <tr key={inc.id ?? i}>
                    <td>{inc.id}</td>
                    <td>
                      {inc.tier !== undefined ? (
                        <span className={`badge badge-t${inc.tier}`}>T{inc.tier}</span>
                      ) : '—'}
                    </td>
                    <td>{inc.status ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
