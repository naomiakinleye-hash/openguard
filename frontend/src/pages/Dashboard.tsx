import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, type HealthResponse, type EventsResponse, type IncidentsResponse } from '../api';
import { useInterval } from '../hooks/useInterval';
import MiniBarChart from '../components/MiniBarChart';

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
  const [error, setError] = useState('');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchAll = useCallback(() => {
    Promise.all([api.health(), api.events(), api.incidents()])
      .then(([h, e, i]) => {
        setHealth(h);
        setEvents(e);
        setIncidents(i);
        setLastUpdated(new Date());
      })
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      );
  }, []);

  useEffect(() => { fetchAll(); }, [fetchAll]);
  useInterval(fetchAll, 30000);

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
            <p style={{ fontSize: '0.75rem', color: '#475569', marginTop: '0.25rem' }}>
              Last updated: {lastUpdated.toLocaleTimeString()}
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
