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

          {/* Evidence Panel — populated by the policy engine */}
          {(incident.explanation || (incident.matched_rules?.length ?? 0) > 0) && (
            <div style={{
              marginTop: '1.5rem',
              borderTop: '1px solid var(--border)',
              paddingTop: '1.25rem',
            }}>
              <h4 style={{ margin: '0 0 1rem', fontSize: '0.95rem', color: 'var(--text-muted)' }}>
                🔍 Evidence &amp; Explainability
              </h4>

              {incident.explanation && (
                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Explanation</div>
                  <div style={{ fontSize: '0.875rem', lineHeight: 1.5 }}>{incident.explanation}</div>
                </div>
              )}

              {incident.confidence !== undefined && incident.confidence > 0 && (
                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                    Confidence — {(incident.confidence * 100).toFixed(0)}%
                  </div>
                  <div style={{ height: '6px', background: 'var(--surface-2)', borderRadius: '3px', overflow: 'hidden' }}>
                    <div style={{
                      width: `${(incident.confidence ?? 0) * 100}%`,
                      height: '100%',
                      background: incident.confidence > 0.7 ? '#e74c3c' : incident.confidence > 0.4 ? '#f39c12' : '#27ae60',
                      borderRadius: '3px',
                      transition: 'width 0.4s ease',
                    }} />
                  </div>
                </div>
              )}

              {incident.blast_radius && (
                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Blast Radius</div>
                  <div style={{ fontSize: '0.875rem', color: '#e67e22' }}>⚠ {incident.blast_radius}</div>
                </div>
              )}

              {(incident.matched_rules?.length ?? 0) > 0 && (
                <div style={{ marginBottom: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Matched Rules</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                    {incident.matched_rules!.map((r) => (
                      <code key={r} style={{
                        background: 'var(--surface-2)', border: '1px solid var(--border)',
                        borderRadius: '4px', padding: '0.15rem 0.5rem', fontSize: '0.8rem',
                      }}>{r}</code>
                    ))}
                  </div>
                </div>
              )}

              {(incident.policy_citations?.length ?? 0) > 0 && (
                <div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Policy Citations</div>
                  <ul style={{ margin: 0, paddingLeft: '1.25rem', fontSize: '0.875rem' }}>
                    {incident.policy_citations!.map((c, i) => <li key={i}>{c}</li>)}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
