import { useEffect, useState } from 'react';
import { api, type SupplyChainEvent, type SupplyChainStats } from '../api';

function RiskBadge({ label, score }: { label: string; score: number }) {
  const color = score >= 70 ? '#e74c3c' : score >= 40 ? '#f39c12' : '#27ae60';
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: '0.35rem',
      background: `${color}22`, color, border: `1px solid ${color}55`,
      borderRadius: '4px', padding: '0.15rem 0.5rem', fontSize: '0.78rem', fontWeight: 600,
    }}>
      {label} ({score.toFixed(0)})
    </span>
  );
}

export default function SupplyChainGuard() {
  const [events, setEvents] = useState<SupplyChainEvent[]>([]);
  const [stats, setStats] = useState<SupplyChainStats | null>(null);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function load(pg: number) {
    setLoading(true);
    try {
      const [res, st] = await Promise.all([
        api.supplyChain(pg),
        api.supplyChainStats(),
      ]);
      setEvents(res.events ?? []);
      setTotal(res.total ?? 0);
      setStats(st);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally { setLoading(false); }
  }

  useEffect(() => { load(page); }, [page]);

  const totalPages = Math.max(1, Math.ceil(total / 50));

  return (
    <div>
      <div className="page-header">
        <h2>Supply Chain Guard</h2>
        <p>Detected package-manager invocations and typosquatting risk indicators from host telemetry.</p>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      {/* Stats row */}
      {stats && (
        <div className="stats-grid" style={{ marginBottom: '1.5rem' }}>
          <div className="stat-card">
            <div className="stat-value">{stats.total}</div>
            <div className="stat-label">Total events</div>
          </div>
          <div className="stat-card">
            <div className="stat-value" style={{ color: '#e74c3c' }}>{stats.high_risk}</div>
            <div className="stat-label">High risk</div>
          </div>
          {Object.entries(stats.installers ?? {}).map(([k, v]) => (
            <div key={k} className="stat-card">
              <div className="stat-value">{v}</div>
              <div className="stat-label">{k}</div>
            </div>
          ))}
        </div>
      )}

      {loading ? <div className="loading">Loading…</div> : events.length === 0 ? (
        <div className="empty-state">
          No supply-chain events detected yet. Package manager invocations will appear here once HostGuard telemetry is processed.
        </div>
      ) : (
        <>
          <div className="card" style={{ padding: 0 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Host</th>
                  <th>Installer</th>
                  <th>Package</th>
                  <th>Version</th>
                  <th>Risk</th>
                  <th>Flags</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => (
                  <tr key={ev.id}>
                    <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {new Date(ev.timestamp).toLocaleString()}
                    </td>
                    <td><code style={{ fontSize: '0.8rem' }}>{ev.host || '—'}</code></td>
                    <td>
                      <span style={{ background: 'var(--surface-2)', padding: '0.15rem 0.5rem', borderRadius: '4px', fontSize: '0.8rem' }}>
                        {ev.installer}
                      </span>
                    </td>
                    <td><strong>{ev.package_name}</strong></td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>{ev.version ?? '—'}</td>
                    <td><RiskBadge label={ev.risk_label} score={ev.risk_score} /></td>
                    <td>
                      {(ev.flags ?? []).map((f) => (
                        <span key={f} style={{
                          background: '#e74c3c22', color: '#e74c3c', border: '1px solid #e74c3c55',
                          borderRadius: '4px', padding: '0.1rem 0.4rem', fontSize: '0.75rem', marginRight: '0.25rem',
                        }}>{f}</span>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="pagination" style={{ marginTop: '1rem', display: 'flex', gap: '0.5rem', justifyContent: 'center' }}>
            <button className="btn-override" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>← Prev</button>
            <span style={{ alignSelf: 'center', color: 'var(--text-muted)' }}>Page {page} / {totalPages}</span>
            <button className="btn-override" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next →</button>
          </div>
        </>
      )}
    </div>
  );
}
