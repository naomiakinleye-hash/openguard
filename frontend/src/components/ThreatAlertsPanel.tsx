import type { Incident } from '../api';

interface ThreatAlertsPanelProps {
  incidents: Incident[] | null;
  loading: boolean;
}

const TIER_META: Record<number, { label: string; bg: string; text: string; border: string }> = {
  0: { label: 'Info',     bg: '#1e293b', text: '#94a3b8', border: '#334155' },
  1: { label: 'Low',      bg: '#1e3a5f', text: '#93c5fd', border: '#1d4ed8' },
  2: { label: 'Medium',   bg: '#3d2800', text: '#fbbf24', border: '#d97706' },
  3: { label: 'High',     bg: '#3d1500', text: '#fb923c', border: '#ea580c' },
  4: { label: 'Critical', bg: '#3d0000', text: '#f87171', border: '#dc2626' },
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
  const active = incidents
    ? incidents
        .filter(inc => parseTier(inc.tier) >= 3)
        .sort((a, b) => parseTier(b.tier) - parseTier(a.tier))
    : [];

  return (
    <div className="card" style={{ marginBottom: '1.5rem', borderLeft: '3px solid #dc2626' }}>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.9375rem' }}>
            Threat Alerts
          </span>
          {!loading && incidents && (
            <span style={{
              fontSize: '0.7rem', fontWeight: 700,
              background: active.length > 0 ? '#991b1b' : '#1e293b',
              color:      active.length > 0 ? '#fca5a5' : '#64748b',
              padding: '1px 8px', borderRadius: 9999,
            }}>
              {active.length} active
            </span>
          )}
        </div>
        <span style={{ fontSize: '0.68rem', color: '#475569', border: '1px solid #334155', borderRadius: 4, padding: '1px 7px' }}>
          Critical + High only
        </span>
      </div>

      {loading ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {[1, 2, 3].map(i => (
            <div key={i} className="loading-skeleton" style={{ height: 48, borderRadius: 6 }} />
          ))}
        </div>
      ) : !incidents ? (
        <div style={{ color: '#475569', fontSize: '0.875rem', padding: '1rem 0' }}>
          Unable to load alerts. Check your connection.
        </div>
      ) : active.length === 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '1.5rem 0', gap: '0.4rem' }}>
          <div style={{ width: 32, height: 32, borderRadius: '50%', background: '#14532d', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <path d="M3 8l3.5 3.5L13 5" stroke="#4ade80" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <p style={{ color: '#16a34a', fontSize: '0.875rem', margin: 0, fontWeight: 600 }}>
            No critical or high threats active
          </p>
          <p style={{ color: '#475569', fontSize: '0.75rem', margin: 0 }}>
            {incidents.length} total incident{incidents.length !== 1 ? 's' : ''} being monitored
          </p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {active.slice(0, 6).map((inc, i) => {
            const tier = parseTier(inc.tier);
            const meta = TIER_META[tier] ?? TIER_META[0];
            return (
              <div key={inc.id ?? i} style={{
                display: 'flex', alignItems: 'center', gap: '0.75rem',
                background: meta.bg, border: `1px solid ${meta.border}`,
                borderRadius: 6, padding: '0.625rem 0.875rem',
              }}>
                <span style={{
                  fontSize: '0.68rem', fontWeight: 700, color: meta.text,
                  background: meta.border + '22', border: `1px solid ${meta.border}`,
                  borderRadius: 4, padding: '2px 8px', whiteSpace: 'nowrap', flexShrink: 0,
                }}>
                  {meta.label}
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: '0.8125rem', color: '#f1f5f9', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    Incident {inc.id ?? '—'}
                  </div>
                  <div style={{ fontSize: '0.73rem', color: '#64748b', marginTop: 2 }}>
                    Status: {inc.status ?? '—'}
                  </div>
                </div>
                <div style={{ fontSize: '0.7rem', color: '#475569', whiteSpace: 'nowrap', flexShrink: 0 }}>
                  {timeAgo(inc.created_at)}
                </div>
              </div>
            );
          })}
          {active.length > 6 && (
            <p style={{ fontSize: '0.75rem', color: '#475569', margin: '0.25rem 0 0', textAlign: 'center' }}>
              +{active.length - 6} more — view all in Incidents
            </p>
          )}
        </div>
      )}

    </div>
  );
}
