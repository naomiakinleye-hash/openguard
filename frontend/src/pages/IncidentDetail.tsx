import { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { api, type Incident } from '../api';
import { useToast } from '../contexts/ToastContext';

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { addToast } = useToast();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    api.incident(id)
      .then((res) => setIncident(res))
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      )
      .finally(() => setLoading(false));
  }, [id]);

  async function handleAction(action: 'approve' | 'deny' | 'override') {
    if (!id) return;
    setBusy(action);
    try {
      const res = await api.incidentAction(id, action);
      addToast(`Incident ${res.incident_id}: ${res.action} — ${res.status}`, 'success');
      navigate('/incidents');
    } catch (err: unknown) {
      addToast(`Error: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setBusy(null);
    }
  }

  return (
    <div>
      <div className="page-header">
        <h2>Incident Detail</h2>
        <p><Link to="/incidents">← Back to Incidents</Link></p>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      {loading ? (
        <div className="loading">Loading…</div>
      ) : !incident ? (
        <div className="empty-state">Incident not found.</div>
      ) : (
        <div className="card" style={{ maxWidth: '640px' }}>
          <dl className="detail-list">
            <dt>Incident ID</dt>
            <dd><code>{incident.id}</code></dd>

            <dt>Type</dt>
            <dd>{incident.type ?? '—'}</dd>

            <dt>Tier</dt>
            <dd>
              {incident.tier !== undefined ? (
                <span className={`badge badge-t${incident.tier}`}>T{incident.tier}</span>
              ) : '—'}
            </dd>

            <dt>Risk Score</dt>
            <dd>{incident.risk_score ?? '—'}</dd>

            <dt>Status</dt>
            <dd>{incident.status ?? '—'}</dd>

            <dt>Created At</dt>
            <dd>{incident.created_at ?? '—'}</dd>

            <dt>Description</dt>
            <dd>{incident.description ?? '—'}</dd>
          </dl>

          <div className="actions-row" style={{ marginTop: '1.5rem' }}>
            <button
              className="btn-approve"
              disabled={busy !== null}
              onClick={() => handleAction('approve')}
            >
              {busy === 'approve' ? '…' : 'Approve'}
            </button>
            <button
              className="btn-deny"
              disabled={busy !== null}
              onClick={() => handleAction('deny')}
            >
              {busy === 'deny' ? '…' : 'Deny'}
            </button>
            <button
              className="btn-override"
              disabled={busy !== null}
              onClick={() => handleAction('override')}
            >
              {busy === 'override' ? '…' : 'Override'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
