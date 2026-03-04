import { useEffect, useState } from 'react';
import { api, type Event } from '../api';

export default function Events() {
  const [events, setEvents] = useState<Event[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    api.events()
      .then((res) => {
        setEvents(res.events);
        setTotal(res.total);
      })
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      )
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <div className="page-header">
        <h2>Events</h2>
        <p>Ingested security events — {total} total</p>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      <div className="table-card">
        <div className="table-header">All Events</div>
        {loading ? (
          <div className="loading">Loading…</div>
        ) : events.length === 0 ? (
          <div className="empty-state">No events recorded yet. Events will appear here once the ingest pipeline receives data.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Event ID</th>
                <th>Type</th>
                <th>Source</th>
                <th>Tier</th>
                <th>Risk Score</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev, i) => (
                <tr key={ev.id ?? i}>
                  <td><code>{ev.id ?? '—'}</code></td>
                  <td>{ev.type ?? '—'}</td>
                  <td>{ev.source ?? '—'}</td>
                  <td>
                    {ev.tier !== undefined ? (
                      <span className={`badge badge-t${ev.tier}`}>T{ev.tier}</span>
                    ) : '—'}
                  </td>
                  <td>{ev.risk_score ?? '—'}</td>
                  <td>{ev.timestamp ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
