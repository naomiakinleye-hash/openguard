import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, type HealthResponse, type EventsResponse, type IncidentsResponse, type Event, type SystemStats, type SummaryResponse } from '../api';
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

  const fetchSummary = useCallback((
    evts: EventsResponse | null,
    incs: IncidentsResponse | null,
    stats: SystemStats | null,
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
    })
      .then((r) => setAiSummary(r))
      .catch((err: unknown) => setSummaryError(
        err instanceof Error ? err.message : 'Could not reach AI provider — set an API key in Model Settings.',
      ))
      .finally(() => setSummaryLoading(false));
  }, [aiSummary]);

  const fetchAll = useCallback(() => {
    Promise.all([api.health(), api.events(), api.incidents(), api.systemStats()])
      .then(([h, e, i, s]) => {
        setHealth(h);
        setEvents(e);
        setIncidents(i);
        setSysStats(s);
        setLastUpdated(new Date());
        // Fetch summary once after first data load (skip on subsequent polls
        // unless the user explicitly triggers regeneration).
        fetchSummary(e, i, s, false);
      })
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      );
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);
  // Keep a REST polling fallback at 5 s in case the SSE connection drops.
  useInterval(fetchAll, 5000);

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

      {/* ── AI Summary ───────────────────────────────────────────────── */}
      <AISummary
        data={aiSummary}
        loading={summaryLoading}
        error={summaryError}
        onRefresh={() => fetchSummary(events, incidents, sysStats, true)}
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
          {sysStats && sysStats.mem_total_mb > 0 ? (
            <>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem', color: '#f1f5f9', fontWeight: 600 }}>
                <span>{sysStats.mem_used_pct.toFixed(1)}%</span>
                <span style={{ color: '#64748b', fontWeight: 400 }}>
                  {(sysStats.mem_used_mb / 1024).toFixed(1)} GB / {(sysStats.mem_total_mb / 1024).toFixed(1)} GB
                </span>
              </div>
              <div style={{ background: '#0f172a', borderRadius: '6px', height: '12px', overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  borderRadius: '6px',
                  width: `${Math.min(100, sysStats.mem_used_pct)}%`,
                  background: sysStats.mem_used_pct >= 85 ? '#dc2626' : sysStats.mem_used_pct >= 60 ? '#d97706' : '#16a34a',
                  transition: 'width 0.6s ease, background 0.4s ease',
                }} />
              </div>
              <div style={{ display: 'flex', gap: '1.25rem', fontSize: '0.75rem', color: '#94a3b8' }}>
                <span><span style={{ color: '#64748b' }}>Used </span>{sysStats.mem_used_mb.toFixed(0)} MB</span>
                <span><span style={{ color: '#64748b' }}>Free </span>{(sysStats.mem_total_mb - sysStats.mem_used_mb).toFixed(0)} MB</span>
              </div>
            </>
          ) : (
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
