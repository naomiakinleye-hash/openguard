import { useCallback, useEffect, useState } from 'react';
import { api, type Event } from '../api';
import { useInterval } from '../hooks/useInterval';
import Pagination from '../components/Pagination';

const PAGE_SIZE = 50;

const TIERS = ['All', 'T0', 'T1', 'T2', 'T3', 'T4'] as const;

export default function Events() {
  const [events, setEvents] = useState<Event[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);

  // Filter state
  const [filterType, setFilterType] = useState('');
  const [filterTier, setFilterTier] = useState('All');
  const [filterSource, setFilterSource] = useState('');

  const fetchEvents = useCallback(() => {
    api.events(page)
      .then((res) => {
        setEvents(res.events);
        setTotal(res.total);
      })
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      )
      .finally(() => setLoading(false));
  }, [page]);

  useEffect(() => { fetchEvents(); }, [fetchEvents]);
  useInterval(fetchEvents, 30000);

  const filtered = events.filter((ev) => {
    if (filterType && !(ev.type ?? '').toLowerCase().includes(filterType.toLowerCase())) return false;
    if (filterTier !== 'All' && ev.tier !== parseInt(filterTier.slice(1))) return false;
    if (filterSource && !(ev.source ?? '').toLowerCase().includes(filterSource.toLowerCase())) return false;
    return true;
  });

  return (
    <div>
      <div className="page-header">
        <h2>Events</h2>
        <p>Ingested security events — {total} total</p>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      <div className="filter-bar">
        <input
          type="text"
          placeholder="Type…"
          value={filterType}
          onChange={(e) => setFilterType(e.target.value)}
        />
        <select
          value={filterTier}
          onChange={(e) => setFilterTier(e.target.value)}
        >
          {TIERS.map((t) => <option key={t}>{t}</option>)}
        </select>
        <input
          type="text"
          placeholder="Source…"
          value={filterSource}
          onChange={(e) => setFilterSource(e.target.value)}
        />
        {(filterType || filterTier !== 'All' || filterSource) && (
          <button className="btn-secondary" onClick={() => { setFilterType(''); setFilterTier('All'); setFilterSource(''); }}>
            Clear
          </button>
        )}
      </div>

      <div className="table-card">
        <div className="table-header">All Events</div>
        {loading ? (
          <div className="loading">Loading…</div>
        ) : filtered.length === 0 ? (
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
              {filtered.map((ev, i) => (
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

      <Pagination page={page} total={total} pageSize={PAGE_SIZE} onPageChange={setPage} />
    </div>
  );
}
