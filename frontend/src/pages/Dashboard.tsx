import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  api,
  type HealthResponse,
  type EventsResponse,
  type IncidentsResponse,
  type SystemStats,
  type HostStatsResponse,
  type AgentStatsResponse,
  type ModelGuardStatsResponse,
  type NetStatsResponse,
  type KPIStats,
  type Event,
} from '../api';
import { useInterval } from '../hooks/useInterval';
import { useSSE } from '../hooks/useSSE';
import MiniBarChart from '../components/MiniBarChart';
import CPUGauge from '../components/CPUGauge';
import KPICharts from '../components/KPICharts';
import VulnerabilityTrends from '../components/VulnerabilityTrends';
import ThreatAlertsPanel from '../components/ThreatAlertsPanel';

const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? '';

const TIER_COLORS: Record<number, string> = {
  0: '#334155',
  1: '#1d4ed8',
  2: '#d97706',
  3: '#ea580c',
  4: '#dc2626',
};

const RISK_BANDS = [
  { label: '0–25',   min: 0,  max: 25,  color: '#16a34a' },
  { label: '26–50',  min: 26, max: 50,  color: '#d97706' },
  { label: '51–75',  min: 51, max: 75,  color: '#ea580c' },
  { label: '76–100', min: 76, max: 100, color: '#dc2626' },
];

export default function Dashboard() {
  const [health,    setHealth]    = useState<HealthResponse | null>(null);
  const [events,    setEvents]    = useState<EventsResponse | null>(null);
  const [incidents, setIncidents] = useState<IncidentsResponse | null>(null);
  const [sysStats,  setSysStats]  = useState<SystemStats | null>(null);
  const [error,     setError]     = useState('');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [liveCount,   setLiveCount]   = useState(0);
  const [hostStats,  setHostStats]  = useState<HostStatsResponse | null>(null);
  const [agentStats, setAgentStats] = useState<AgentStatsResponse | null>(null);
  const [modelStats, setModelStats] = useState<ModelGuardStatsResponse | null>(null);
  const [netStats,   setNetStats]   = useState<NetStatsResponse | null>(null);
  const [kpiStats,   setKpiStats]   = useState<KPIStats | null>(null);

  const fetchAll = useCallback(() => {
    api.hostGuardStats().then(setHostStats).catch(() => {});
    api.agentStats().then(setAgentStats).catch(() => {});
    api.modelGuardStats().then(setModelStats).catch(() => {});
    api.networkGuardStats().then(setNetStats).catch(() => {});
    api.kpiStats().then(setKpiStats).catch(() => {});

    Promise.all([api.health(), api.events(), api.incidents(), api.systemStats()])
      .then(([h, e, i, s]) => {
        setHealth(h);
        setEvents(e);
        setIncidents(i);
        setSysStats(s);
        setLastUpdated(new Date());
      })
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      );
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);
  useInterval(fetchAll, 5000);

  const token = localStorage.getItem('og_token') ?? '';
  const sseUrl = useMemo(
    () => (token ? `${BASE}/api/v1/events/stream?token=${encodeURIComponent(token)}` : null),
    [token],
  );

  const handleLiveEvent = useCallback((data: unknown) => {
    const event = data as Event;
    setEvents((prev) => {
      if (!prev) return prev;
      const exists = prev.events.some((e) => e.id && e.id === event.id);
      if (exists) return prev;
      return { ...prev, events: [event, ...prev.events], total: prev.total + 1 };
    });
    setLastUpdated(new Date());
    setLiveCount((n) => n + 1);
  }, []);

  useSSE(sseUrl, handleLiveEvent);

  function parseTier(t: unknown): number | undefined {
    if (typeof t === 'number') return t;
    if (typeof t === 'string') {
      if (/^T(\d)$/i.test(t)) return parseInt(t.slice(1), 10);
      const n = parseInt(t, 10);
      if (!isNaN(n)) return n;
    }
    return undefined;
  }

  const tierCounts = [0, 1, 2, 3, 4].map((tier) => ({
    tier,
    count: events?.events.filter((e) => parseTier(e.tier) === tier).length ?? 0,
  }));
  const totalEvents = events?.events.length ?? 0;

  const riskCounts = RISK_BANDS.map((band) => ({
    ...band,
    count: events?.events.filter((e) => {
      const s = e.risk_score as number | undefined;
      return s !== undefined && s >= band.min && s <= band.max;
    }).length ?? 0,
  }));

  const healthStatus = health?.status ?? null;
  const healthColor =
    healthStatus === 'ok' ? '#16a34a' :
    healthStatus === 'degraded' ? '#d97706' : '#dc2626';

  return (
    <div style={{ padding: '0 0 2rem' }}>

      {/* ── Page header ── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '1.75rem' }}>
        <div>
          <h2 style={{ fontSize: '1.375rem', fontWeight: 700, color: '#f1f5f9', margin: 0 }}>
            Dashboard
          </h2>
          <p style={{ color: '#64748b', fontSize: '0.875rem', margin: '0.25rem 0 0' }}>
            OpenGuard v5 — Security Operations Overview
          </p>
          {lastUpdated && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.375rem' }}>
              <span style={{ fontSize: '0.75rem', color: '#475569' }}>
                Updated {lastUpdated.toLocaleTimeString()}
              </span>
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: '0.3rem',
                fontSize: '0.68rem', fontWeight: 700, color: '#16a34a',
                border: '1px solid #16a34a', borderRadius: '4px', padding: '1px 7px',
              }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#16a34a', animation: 'pulse 2s infinite' }} />
                LIVE{liveCount > 0 ? ` +${liveCount}` : ''}
              </span>
            </div>
          )}
        </div>
        <button className="btn-secondary" onClick={fetchAll} style={{ marginTop: '0.25rem' }}>
          Refresh
        </button>
      </div>

      {error && (
        <div className="error-msg" style={{ marginBottom: '1.5rem' }}>
          {error}
        </div>
      )}

      {/* ── Top KPI row ── */}
      <div className="kpi-row">

        <div className="kpi-card">
          <span className="kpi-label">System Health</span>
          {health ? (
            <span className="kpi-value" style={{ color: healthColor, fontSize: '1.5rem' }}>
              {health.status.toUpperCase()}
            </span>
          ) : (
            <span className="kpi-value kpi-empty">—</span>
          )}
          <span className="kpi-sub">Platform status</span>
        </div>

        <div className="kpi-card">
          <span className="kpi-label">Total Events</span>
          <span className="kpi-value">{events ? events.total.toLocaleString() : '—'}</span>
          <span className="kpi-sub">All recorded events</span>
        </div>

        <div className="kpi-card">
          <span className="kpi-label">Active Incidents</span>
          <span className="kpi-value" style={{ color: (incidents?.total ?? 0) > 0 ? '#ea580c' : '#f1f5f9' }}>
            {incidents ? incidents.total : '—'}
          </span>
          <span className="kpi-sub">Requiring attention</span>
        </div>

        <div className="kpi-card">
          <span className="kpi-label">Platform Version</span>
          <span className="kpi-value" style={{ fontSize: '1.5rem' }}>{health ? health.version : '—'}</span>
          <span className="kpi-sub">Current release</span>
        </div>

      </div>

      {/* ── Module cards ── */}
      <div className="section-label">Security Modules</div>
      <div className="module-grid">

        <div className="module-card" style={{ borderTop: '3px solid #ea580c' }}>
          <div className="module-header">
            <span className="module-title">HostGuard</span>
            <Link to="/hostguard" className="module-link">View all</Link>
          </div>
          <div className="module-stats">
            <div className="module-stat">
              <span className="module-stat-value">{hostStats?.total_events ?? '—'}</span>
              <span className="module-stat-label">Total Events</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value" style={{ color: '#ea580c' }}>{hostStats?.threat_events ?? '—'}</span>
              <span className="module-stat-label">Threats</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value">{hostStats?.unique_hosts ?? '—'}</span>
              <span className="module-stat-label">Hosts</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value">{hostStats?.active_rules ?? '—'}</span>
              <span className="module-stat-label">Rules</span>
            </div>
          </div>
        </div>

        <div className="module-card" style={{ borderTop: '3px solid #7c3aed' }}>
          <div className="module-header">
            <span className="module-title">AgentGuard</span>
            <Link to="/agentguard" className="module-link">View all</Link>
          </div>
          <div className="module-stats">
            <div className="module-stat">
              <span className="module-stat-value" style={{ color: '#4ade80' }}>{agentStats?.active_agents ?? '—'}</span>
              <span className="module-stat-label">Active</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value" style={{ color: '#ea580c' }}>{agentStats?.quarantine_count ?? '—'}</span>
              <span className="module-stat-label">Quarantined</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value" style={{ color: '#d97706' }}>{agentStats?.suspended_count ?? '—'}</span>
              <span className="module-stat-label">Suspended</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value" style={{ color: '#dc2626' }}>{agentStats?.total_threats ?? '—'}</span>
              <span className="module-stat-label">Threats</span>
            </div>
          </div>
        </div>

        <div className="module-card" style={{ borderTop: '3px solid #2563eb' }}>
          <div className="module-header">
            <span className="module-title">ModelGuard</span>
            <Link to="/modelguard" className="module-link">View all</Link>
          </div>
          <div className="module-stats">
            <div className="module-stat">
              <span className="module-stat-value">{modelStats?.total_calls ?? '—'}</span>
              <span className="module-stat-label">Total Calls</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value" style={{ color: '#dc2626' }}>{modelStats?.blocked_calls ?? '—'}</span>
              <span className="module-stat-label">Blocked</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value">{modelStats ? `${modelStats.avg_latency_ms}ms` : '—'}</span>
              <span className="module-stat-label">Avg Latency</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value" style={{ color: '#4ade80' }}>
                {modelStats ? `${((modelStats.avg_confidence ?? 0) * 100).toFixed(0)}%` : '—'}
              </span>
              <span className="module-stat-label">Confidence</span>
            </div>
          </div>
        </div>

        <div className="module-card" style={{ borderTop: '3px solid #16a34a' }}>
          <div className="module-header">
            <span className="module-title">NetworkGuard</span>
            <Link to="/networkguard" className="module-link">View all</Link>
          </div>
          <div className="module-stats">
            <div className="module-stat">
              <span className="module-stat-value">{netStats?.total_events ?? '—'}</span>
              <span className="module-stat-label">Total Events</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value" style={{ color: '#f87171' }}>{netStats?.threat_events ?? '—'}</span>
              <span className="module-stat-label">Threats</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value">{netStats?.unique_sources ?? '—'}</span>
              <span className="module-stat-label">Sources</span>
            </div>
            <div className="module-stat">
              <span className="module-stat-value" style={{ color: '#fb923c' }}>{netStats?.blocked_flows ?? '—'}</span>
              <span className="module-stat-label">Blocked</span>
            </div>
          </div>
        </div>

      </div>

      {/* ── KPI Charts ── */}
      <KPICharts kpi={kpiStats} />

      {/* ── Vulnerability Trends ── */}
      <VulnerabilityTrends />

      {/* ── Threat Alerts ── */}
      <ThreatAlertsPanel incidents={incidents?.incidents ?? null} loading={!incidents} />

      {/* ── CPU & Memory ── */}
      <div className="section-label">System Resources</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>

        <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
          <div className="section-title" style={{ alignSelf: 'flex-start', marginBottom: '0.25rem' }}>CPU Utilisation</div>
          <CPUGauge utilPct={sysStats ? sysStats.cpu_util_pct : -1} size={130} />
          <div style={{ display: 'flex', gap: '1.25rem', fontSize: '0.75rem', color: '#94a3b8' }}>
            <span><span style={{ color: '#64748b' }}>Cores </span>{sysStats ? sysStats.cpu_cores : '—'}</span>
            <span><span style={{ color: '#64748b' }}>1m </span>{sysStats ? sysStats.load_avg_1m.toFixed(2) : '—'}</span>
            <span><span style={{ color: '#64748b' }}>5m </span>{sysStats ? sysStats.load_avg_5m.toFixed(2) : '—'}</span>
            <span><span style={{ color: '#64748b' }}>15m </span>{sysStats ? sysStats.load_avg_15m.toFixed(2) : '—'}</span>
          </div>
        </div>

        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: '0.75rem' }}>
          <div className="section-title">Memory Utilisation</div>
          {sysStats && sysStats.mem_total_mb > 0 ? (() => {
            const APP_COLORS = ['#3b82f6','#8b5cf6','#ec4899','#f59e0b','#06b6d4','#10b981','#f97316'];
            const usedPct = Math.min(100, sysStats.mem_used_pct);
            const apps = sysStats.mem_apps ?? [];
            const totalMB = sysStats.mem_total_mb;
            const appTotal = apps.reduce((s, a) => s + a.mem_mb, 0);
            const freeMB = Math.max(0, totalMB - appTotal);
            const segments = [
              ...apps.map((a, i) => ({ label: a.name, mb: a.mem_mb, pct: (a.mem_mb / totalMB) * 100, color: a.name === 'Other' ? '#374151' : APP_COLORS[i % APP_COLORS.length] })),
              { label: 'Free', mb: freeMB, pct: (freeMB / totalMB) * 100, color: '#1e3a5f' },
            ];
            return (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.875rem', color: '#f1f5f9', fontWeight: 600 }}>
                  <span>{usedPct.toFixed(1)}% used</span>
                  <span style={{ color: '#64748b', fontWeight: 400 }}>{(sysStats.mem_used_mb / 1024).toFixed(1)} GB / {(totalMB / 1024).toFixed(1)} GB</span>
                </div>
                <div style={{ display: 'flex', borderRadius: '6px', overflow: 'hidden', height: '12px', background: '#0f172a' }}>
                  {segments.map(seg => seg.pct > 0.2 && (
                    <div key={seg.label} style={{ width: `${seg.pct}%`, background: seg.color, transition: 'width 0.6s ease' }} title={`${seg.label}: ${seg.mb.toFixed(0)} MB (${seg.pct.toFixed(1)}%)`} />
                  ))}
                </div>
                <div style={{ display: 'flex', gap: '0.75rem 1.25rem', flexWrap: 'wrap' }}>
                  {segments.filter(s => s.pct > 0.2).map(seg => (
                    <div key={seg.label} style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: seg.color, display: 'inline-block', flexShrink: 0 }} />
                      <span style={{ fontSize: '0.73rem', color: '#94a3b8' }}>
                        {seg.label}<strong style={{ color: '#e2e8f0' }}> {seg.mb.toFixed(0)}MB</strong>
                        <span style={{ color: '#475569' }}> {seg.pct.toFixed(1)}%</span>
                      </span>
                    </div>
                  ))}
                </div>
              </>
            );
          })() : (
            <div style={{ color: '#475569', fontSize: '0.875rem' }}>Awaiting data...</div>
          )}
        </div>

      </div>

      {/* ── Tier + Risk breakdown ── */}
      {events && (
        <>
          <div className="section-label">Event Breakdown</div>
          <div className="card-grid">
            <div className="card">
              <div className="section-title">Tier Breakdown</div>
              {tierCounts.map(({ tier, count }) => (
                <MiniBarChart key={tier} label={`T${tier}`} value={count} max={totalEvents} color={TIER_COLORS[tier]} />
              ))}
            </div>
            <div className="card">
              <div className="section-title">Risk Score Distribution</div>
              {riskCounts.map((band) => (
                <MiniBarChart key={band.label} label={band.label} value={band.count} max={totalEvents} color={band.color} />
              ))}
            </div>
          </div>
        </>
      )}

      {/* ── Recent events + incidents ── */}
      <div className="section-label">Recent Activity</div>
      <div className="card-grid">

        <div className="table-card">
          <div className="table-header">
            Recent Events
            <Link to="/events" style={{ fontSize: '0.8125rem', fontWeight: 400, marginLeft: '0.5rem' }}>View all</Link>
          </div>
          {!events ? (
            <div className="loading">Loading...</div>
          ) : events.events.length === 0 ? (
            <div className="empty-state">No events recorded yet.</div>
          ) : (
            <table>
              <thead>
                <tr><th>ID</th><th>Type</th><th>Tier</th><th>Timestamp</th></tr>
              </thead>
              <tbody>
                {events.events.slice(0, 5).map((ev, i) => (
                  <tr key={ev.id ?? i}>
                    <td>{ev.id ?? '—'}</td>
                    <td>{ev.type ?? '—'}</td>
                    <td>{ev.tier !== undefined ? <span className={`badge badge-t${ev.tier}`}>T{ev.tier}</span> : '—'}</td>
                    <td>{ev.timestamp ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="table-card">
          <div className="table-header">
            Active Incidents
            <Link to="/incidents" style={{ fontSize: '0.8125rem', fontWeight: 400, marginLeft: '0.5rem' }}>View all</Link>
          </div>
          {!incidents ? (
            <div className="loading">Loading...</div>
          ) : incidents.incidents.length === 0 ? (
            <div className="empty-state">No active incidents.</div>
          ) : (
            <table>
              <thead>
                <tr><th>ID</th><th>Tier</th><th>Status</th></tr>
              </thead>
              <tbody>
                {incidents.incidents.slice(0, 5).map((inc, i) => (
                  <tr key={inc.id ?? i}>
                    <td>{inc.id}</td>
                    <td>{inc.tier !== undefined ? <span className={`badge badge-t${inc.tier}`}>T{inc.tier}</span> : '—'}</td>
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
