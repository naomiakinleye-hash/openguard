import type { Incident } from '../api';

interface ThreatAlertsPanelProps {
  incidents: Incident[] | null;
  loading: boolean;
}

const TIER_COLORS: Record<number, { bg: string; text: string; border: string; label: string }> = {
  0: { bg: '#1e293b', text: '#94a3b8', border: '#334155',  label: 'Info'     },
  1: { bg: '#1e3a5f', text: '#93c5fd', border: '#1d4ed8',  label: 'Low'      },
  2: { bg: '#3d2800', text: '#fbbf24', border: '#d97706',  label: 'Medium'   },
  3: { bg: '#3d1500', text: '#fb923c', border: '#ea580c',  label: 'High'     },
  4: { bg: '#3d0000', text: '#f87171', border: '#dc2626',  label: 'Critical' },
};

function parseTier(t: unknown): number {
  if (typeof t === 'number') return t;
  if (typeof t === 'string') {
    if (/^T(\d)$/i.test(t)) return parseInt(t.slice(1), 10);
    const n = parseInt(t, 10);
    if (!isNaN(n)) return n;
  }
  return 0;
}

function timeAgo(ts: string | undefined): string {
  if (!ts) return '—';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1)  return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)  return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function ThreatAlertsPanel({ incidents, loading }: ThreatAlertsPanelProps) {
  const criticalAndHigh = incidents
    ? incidents.filter(inc => parseTier(inc.tier) >= 3).sort((a, b) => parseTier(b.tier) - parseTier(a.tier))
    : [];

  return (
    <div className="card" style={{ marginBottom: '1.5rem', borderLeft: '3px solid #dc2626' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '1rem' }}>🚨</span>
          <span style={{ fontWeight: 600, color: '#f1f5f9', fontSize: '0.9375rem' }}>
            Threat Alerts
          </span>
          {!loading && incidents && (
            <span style={{
              background: criticalAndHigh.length > 0 ? '#991b1b' : '#1e293b',
              color: criticalAndHigh.length > 0 ? '#fca5a5' : '#64748b',
              fontSize: '0.7rem', fontWeight: 700,
              padding: '1px 7px', borderRadius: 9999,
            }}>
              {criticalAndHigh.length} active
            </span>
          )}
        </div>
        <span style={{
          fontSize: '0.68rem', color: '#475569',
          border: '1px solid #334155', borderRadius: '4px', padding: '1px 6px',
        }}>
          Critical + High only
        </span>
      </div>

      {/* Content */}
      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {[1,2,3].map(i => (
            <div key={i} className="loading-skeleton" style={{ height: '52px', borderRadius: 6 }} />
          ))}
        </div>
      ) : !incidents ? (
        <div style={{ color: '#475569', fontSize: '0.875rem', padding: '1rem 0' }}>
          Unable to load alerts. Check your backend connection.
        </div>
      ) : criticalAndHigh.length === 0 ? (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          padding: '1.5rem 0', gap: '0.5rem',
        }}>
          <span style={{ fontSize: '1.5rem' }}>✅</span>
          <p style={{ color: '#16a34a', fontSize: '0.875rem', margin: 0, fontWeight: 600 }}>
            No critical or high threats active
          </p>
          <p style={{ color: '#475569', fontSize: '0.75rem', margin: 0 }}>
            {incidents.length} total incident{incidents.length !== 1 ? 's' : ''} being monitored
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
          {criticalAndHigh.slice(0, 6).map((inc, i) => {
            const tier  = parseTier(inc.tier);
            const style = TIER_COLORS[tier] ?? TIER_COLORS[0];
            return (
              <div key={inc.id ?? i} style={{
                display: 'flex', alignItems: 'center', gap: '0.75rem',
                background: style.bg, border: `1px solid ${style.border}`,
                borderRadius: 6, padding: '0.625rem 0.875rem',
              }}>
                {/* Severity pill */}
                <span style={{
                  fontSize: '0.68rem', fontWeight: 700, color: style.text,
                  background: style.border + '33',
                  border: `1px solid ${style.border}`,
                  borderRadius: 4, padding: '2px 7px', whiteSpace: 'nowrap', flexShrink: 0,
                }}>
                  {style.label}
                </span>

                {/* Details */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '0.8125rem', color: '#f1f5f9', fontWeight: 600,
                    whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    Incident {inc.id ?? '—'}
                  </div>
                  <div style={{ fontSize: '0.73rem', color: '#64748b', marginTop: 2 }}>
                    Status: {inc.status ?? '—'}
                  </div>
                </div>

                {/* Time */}
                <div style={{ fontSize: '0.7rem', color: '#475569', whiteSpace: 'nowrap', flexShrink: 0 }}>
                  {timeAgo(inc.created_at)}
                </div>
              </div>
            );
          })}
          {criticalAndHigh.length > 6 && (
            <p style={{ fontSize: '0.75rem', color: '#475569', margin: '0.25rem 0 0', textAlign: 'center' }}>
              +{criticalAndHigh.length - 6} more — view all in Incidents
            </p>
          )}
        </div>
      )}
    </div>
  );
}
