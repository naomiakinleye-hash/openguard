import { useEffect, useState } from 'react';
import { api, type Incident } from '../api';

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actionMsg, setActionMsg] = useState('');
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    api.incidents()
      .then((res) => {
        setIncidents(res.incidents);
        setTotal(res.total);
      })
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      )
      .finally(() => setLoading(false));
  }, []);

  async function handleAction(id: string, action: 'approve' | 'deny' | 'override') {
    setBusy(`${id}:${action}`);
    setActionMsg('');
    try {
      const res = await api.incidentAction(id, action);
      setActionMsg(`Incident ${res.incident_id}: ${res.action} — ${res.status}`);
    } catch (err: unknown) {
      setActionMsg(`Error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <div className="page-header">
        <h2>Incidents</h2>
        <p>Active incidents requiring human review — {total} total</p>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}
      {actionMsg && <div className="card" style={{ marginBottom: '1rem', color: '#a3e635' }}>{actionMsg}</div>}

      <div className="table-card">
        <div className="table-header">All Incidents</div>
        {loading ? (
          <div className="loading">Loading…</div>
        ) : incidents.length === 0 ? (
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
              {incidents.map((inc) => (
                <tr key={inc.id}>
                  <td><code>{inc.id}</code></td>
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
    </div>
  );
}
