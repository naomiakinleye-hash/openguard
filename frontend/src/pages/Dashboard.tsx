import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, type HealthResponse, type EventsResponse, type IncidentsResponse } from '../api';

export default function Dashboard() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [events, setEvents] = useState<EventsResponse | null>(null);
  const [incidents, setIncidents] = useState<IncidentsResponse | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([api.health(), api.events(), api.incidents()])
      .then(([h, e, i]) => {
        setHealth(h);
        setEvents(e);
        setIncidents(i);
      })
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      );
  }, []);

  return (
    <div>
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>OpenGuard v5 — Security Operations Overview</p>
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
