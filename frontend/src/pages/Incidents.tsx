import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, type Incident } from '../api';
import { useInterval } from '../hooks/useInterval';
import { useToast } from '../contexts/ToastContext';
import Pagination from '../components/Pagination';

const PAGE_SIZE = 50;
const TIERS = ['All', 'T0', 'T1', 'T2', 'T3', 'T4'] as const;

export default function Incidents() {
  const { addToast } = useToast();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [page, setPage] = useState(1);

  // Filter state
  const [filterStatus, setFilterStatus] = useState('');
  const [filterTier, setFilterTier] = useState('All');

  const fetchIncidents = useCallback(() => {
    api.incidents(page)
      .then((res) => {
        setIncidents(res.incidents);
        setTotal(res.total);
      })
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      )
      .finally(() => setLoading(false));
  }, [page]);

  useEffect(() => { fetchIncidents(); }, [fetchIncidents]);
  useInterval(fetchIncidents, 30000);

  async function handleAction(id: string, action: 'approve' | 'deny' | 'override') {
    setBusy(`${id}:${action}`);
    try {
      const res = await api.incidentAction(id, action);
      addToast(`Incident ${res.incident_id}: ${res.action} — ${res.status}`, 'success');
    } catch (err: unknown) {
      addToast(`Error: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setBusy(null);
    }
  }

  const filtered = incidents.filter((inc) => {
    if (filterStatus && !(inc.status ?? '').toLowerCase().includes(filterStatus.toLowerCase())) return false;
    if (filterTier !== 'All' && inc.tier !== parseInt(filterTier.slice(1))) return false;
    return true;
  });

  return (
    <div>
      <div className="page-header">
        <h2>Incidents</h2>
        <p>Active incidents requiring human review — {total} total</p>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      <div className="filter-bar">
        <input
          type="text"
          placeholder="Status…"
          value={filterStatus}
          onChange={(e) => setFilterStatus(e.target.value)}
        />
        <select
          value={filterTier}
          onChange={(e) => setFilterTier(e.target.value)}
        >
          {TIERS.map((t) => <option key={t}>{t}</option>)}
        </select>
        {(filterStatus || filterTier !== 'All') && (
          <button className="btn-secondary" onClick={() => { setFilterStatus(''); setFilterTier('All'); }}>
            Clear
          </button>
        )}
      </div>

      <div className="table-card">
        <div className="table-header">All Incidents</div>
        {loading ? (
          <div className="loading">Loading…</div>
        ) : filtered.length === 0 ? (
          <div className="empty-state">No active incidents. The system will surface incidents here when detection thresholds are exceeded.</div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Type</th>
                <th>Tier</th>
                <th>Risk Score</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((inc) => (
                <tr key={inc.id}>
                  <td><code><Link to={`/incidents/${inc.id}`}>{inc.id}</Link></code></td>
                  <td>{inc.type ?? '—'}</td>
                  <td>
                    {inc.tier !== undefined ? (
                      <span className={`badge badge-t${inc.tier}`}>T{inc.tier}</span>
                    ) : '—'}
                  </td>
                  <td>{inc.risk_score ?? '—'}</td>
                  <td>{inc.status ?? '—'}</td>
                  <td>{inc.created_at ?? '—'}</td>
                  <td>
                    <div className="actions-row">
                      <button
                        className="btn-approve"
                        disabled={busy !== null}
                        onClick={() => handleAction(inc.id, 'approve')}
                      >
                        {busy === `${inc.id}:approve` ? '…' : 'Approve'}
                      </button>
                      <button
                        className="btn-deny"
                        disabled={busy !== null}
                        onClick={() => handleAction(inc.id, 'deny')}
                      >
                        {busy === `${inc.id}:deny` ? '…' : 'Deny'}
                      </button>
                      <button
                        className="btn-override"
                        disabled={busy !== null}
                        onClick={() => handleAction(inc.id, 'override')}
                      >
                        {busy === `${inc.id}:override` ? '…' : 'Override'}
                      </button>
                    </div>
                  </td>
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
