import { useCallback, useEffect, useMemo, useState } from 'react';
import { api, type SensorInfo } from '../api';
import { useInterval } from '../hooks/useInterval';

// ─── Constants ────────────────────────────────────────────────────────────────

const SENSOR_META: Record<string, { icon: string; color: string; bg: string; tag: string }> = {
  hostguard: { icon: '🖥️', color: '#ea580c', bg: '#431407', tag: 'Host' },
  agentguard: { icon: '🤖', color: '#7c3aed', bg: '#2e1065', tag: 'Agent' },
  commsguard: { icon: '💬', color: '#059669', bg: '#022c22', tag: 'Comms' },
};
const FALLBACK_META = { icon: '🔬', color: '#475569', bg: '#1e293b', tag: 'Sensor' };

const SUB_PALETTE = [
  { color: '#2563eb', bg: '#1e3a5f' },
  { color: '#7c3aed', bg: '#2e1065' },
  { color: '#059669', bg: '#022c22' },
  { color: '#ea580c', bg: '#431407' },
  { color: '#db2777', bg: '#500724' },
  { color: '#0891b2', bg: '#082f49' },
  { color: '#d97706', bg: '#422006' },
];

// ─── Copy button ──────────────────────────────────────────────────────────────

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  function handleCopy() {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }
  return (
    <button
      onClick={handleCopy}
      title="Copy to clipboard"
      style={{
        marginLeft: '0.375rem', background: 'none', border: 'none',
        color: copied ? '#4ade80' : '#475569', cursor: 'pointer',
        fontSize: '0.75rem', padding: 0, transition: 'color 0.2s',
      }}
    >
      {copied ? '✓' : '⎘'}
    </button>
  );
}

// ─── Config table ─────────────────────────────────────────────────────────────

function ConfigTable({ config }: { config: Record<string, unknown> }) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
        <thead>
          <tr style={{ background: '#0f172a', borderBottom: '1px solid #334155' }}>
            <th style={{ padding: '0.5rem 1rem', textAlign: 'left', color: '#64748b', fontWeight: 600, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', width: '14rem' }}>
              Key
            </th>
            <th style={{ padding: '0.5rem 1rem', textAlign: 'left', color: '#64748b', fontWeight: 600, fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Value
            </th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(config).map(([key, value], idx) => (
            <tr key={key} style={{ borderTop: idx > 0 ? '1px solid #1e293b' : 'none' }}>
              <td style={{ padding: '0.5rem 1rem', fontFamily: 'monospace', fontSize: '0.75rem', color: '#64748b', verticalAlign: 'top', whiteSpace: 'nowrap' }}>
                {key}
              </td>
              <td style={{ padding: '0.5rem 1rem', verticalAlign: 'top' }}>
                {Array.isArray(value) ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                    {(value as unknown[]).map((v, i) => (
                      <span key={i} style={{ display: 'inline-flex', alignItems: 'center' }}>
                        <code style={{ fontFamily: 'monospace', fontSize: '0.75rem', background: '#1e3a5f', color: '#60a5fa', padding: '0.125rem 0.375rem', borderRadius: '4px' }}>
                          {String(v)}
                        </code>
                        <CopyButton text={String(v)} />
                      </span>
                    ))}
                  </div>
                ) : (
                  <span style={{ display: 'inline-flex', alignItems: 'center' }}>
                    <code style={{ fontFamily: 'monospace', fontSize: '0.75rem', background: '#022c22', color: '#4ade80', padding: '0.125rem 0.375rem', borderRadius: '4px' }}>
                      {String(value)}
                    </code>
                    <CopyButton text={String(value)} />
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ─── Sensor card ──────────────────────────────────────────────────────────────

function SensorCard({ sensor, highlight }: { sensor: SensorInfo; highlight: string }) {
  const [showConfig, setShowConfig] = useState(false);
  const meta = SENSOR_META[sensor.id] ?? FALLBACK_META;

  const isNats    = sensor.listen_addr.toLowerCase().includes('nats');
  const natsTopic = sensor.config['nats_topic'] as string | undefined;

  const highlightedSubs = useMemo(() => {
    if (!highlight) return sensor.subsystems;
    const lc = highlight.toLowerCase();
    return sensor.subsystems.filter((s) => s.toLowerCase().includes(lc));
  }, [sensor.subsystems, highlight]);

  const showAll = !highlight;

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden', borderLeft: `3px solid ${meta.color}` }}>
      {/* Header */}
      <div style={{ padding: '1.25rem 1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
          <span style={{ fontSize: '2rem', flexShrink: 0, marginTop: '0.125rem' }}>{meta.icon}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.375rem' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f1f5f9', margin: 0 }}>{sensor.name}</h3>
              <span style={{
                padding: '0.125rem 0.5rem', borderRadius: '9999px',
                background: meta.bg, border: `1px solid ${meta.color}`,
                color: meta.color, fontSize: '0.7rem', fontWeight: 700,
                textTransform: 'uppercase', letterSpacing: '0.06em',
              }}>
                {meta.tag}
              </span>
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: '0.3rem',
                padding: '0.125rem 0.5rem', borderRadius: '9999px',
                background: '#052e16', border: '1px solid #16a34a',
                color: '#4ade80', fontSize: '0.7rem', fontWeight: 700,
              }}>
                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#4ade80', animation: 'pulse 2s infinite' }} />
                Active
              </span>
            </div>
            <p style={{ fontSize: '0.875rem', color: '#94a3b8', margin: 0, lineHeight: 1.5 }}>{sensor.description}</p>
          </div>
        </div>

        {/* Transport row */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', marginTop: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              {isNats ? 'Transport' : 'Listen'}
            </span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontFamily: 'monospace', fontSize: '0.75rem', background: '#0f172a', color: '#94a3b8', padding: '0.25rem 0.625rem', borderRadius: '6px', border: '1px solid #334155' }}>
              {isNats ? '📨 NATS' : sensor.listen_addr}
              {!isNats && <CopyButton text={sensor.listen_addr} />}
            </span>
          </div>
          {natsTopic && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontSize: '0.7rem', fontWeight: 600, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Topic</span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem', fontFamily: 'monospace', fontSize: '0.75rem', background: '#1e3a5f', color: '#60a5fa', padding: '0.25rem 0.625rem', borderRadius: '6px', border: '1px solid #2563eb' }}>
                {natsTopic}
                <CopyButton text={natsTopic} />
              </span>
            </div>
          )}
        </div>

        {/* Subsystem pills */}
        <div style={{ marginTop: '1rem' }}>
          <div style={{ fontSize: '0.7rem', fontWeight: 600, color: '#475569', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.5rem' }}>
            Subsystems / Channels ({sensor.subsystems.length})
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
            {(showAll ? sensor.subsystems : highlightedSubs).map((sub, idx) => {
              const pal = SUB_PALETTE[idx % SUB_PALETTE.length];
              const isMatch = highlight && sub.toLowerCase().includes(highlight.toLowerCase());
              return (
                <span
                  key={sub}
                  style={{
                    padding: '0.25rem 0.625rem', borderRadius: '9999px',
                    background: pal.bg, border: `1px solid ${pal.color}`,
                    color: pal.color, fontSize: '0.75rem', fontWeight: 500,
                    outline: isMatch ? '2px solid #fbbf24' : 'none',
                    outlineOffset: '2px',
                  }}
                >
                  {sub.replace(/_/g, ' ')}
                </span>
              );
            })}
            {!showAll && highlightedSubs.length === 0 && (
              <span style={{ fontSize: '0.75rem', color: '#475569' }}>No matching subsystems</span>
            )}
            {!showAll && highlightedSubs.length < sensor.subsystems.length && (
              <span style={{ fontSize: '0.75rem', color: '#475569', alignSelf: 'center' }}>
                +{sensor.subsystems.length - highlightedSubs.length} more hidden
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Config toggle */}
      <div style={{ borderTop: '1px solid #334155' }}>
        <button
          onClick={() => setShowConfig((v) => !v)}
          style={{
            width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '0.75rem 1.5rem', background: 'none', border: 'none', cursor: 'pointer',
            fontSize: '0.875rem', color: '#64748b', fontWeight: 500,
          }}
          onMouseEnter={(e) => (e.currentTarget.style.background = '#0f172a')}
          onMouseLeave={(e) => (e.currentTarget.style.background = 'none')}
        >
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span>⚙️</span>
            Default Configuration
            <span style={{ fontSize: '0.75rem', color: '#334155' }}>
              ({Object.keys(sensor.config).length} keys)
            </span>
          </span>
          <span style={{ transition: 'transform 0.2s', transform: showConfig ? 'rotate(180deg)' : 'rotate(0deg)', color: '#475569' }}>▾</span>
        </button>

        {showConfig && (
          <div style={{ borderTop: '1px solid #334155' }}>
            <ConfigTable config={sensor.config} />
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function Sensors() {
  const [sensors, setSensors] = useState<SensorInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState('');
  const [search, setSearch]   = useState('');

  const load = useCallback(() => {
    setLoading(true);
    setError('');
    api.sensors()
      .then((res) => setSensors(res.sensors))
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);
  useInterval(load, 30000);

  const filteredSensors = useMemo(() => {
    const lc = search.toLowerCase();
    if (!lc) return sensors;
    return sensors.filter(
      (s) =>
        s.name.toLowerCase().includes(lc) ||
        s.id.toLowerCase().includes(lc) ||
        s.description.toLowerCase().includes(lc) ||
        s.subsystems.some((sub) => sub.toLowerCase().includes(lc)),
    );
  }, [sensors, search]);

  const totalSubsystems = sensors.reduce((acc, s) => acc + s.subsystems.length, 0);
  const natsCount       = sensors.filter((s) => s.listen_addr.toLowerCase().includes('nats')).length;
  const totalConfigKeys = sensors.reduce((acc, s) => acc + Object.keys(s.config).length, 0);

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

      {/* ─── Header ───────────────────────────────────────────────────────────── */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '1rem' }}>
        <div>
          <h2>🔬 Sensors</h2>
          <p>Deployed sensor adapters, their subsystems, and default configurations</p>
        </div>
        <button className="btn-secondary" onClick={load} disabled={loading} style={{ fontSize: '0.875rem', fontWeight: 600, flexShrink: 0, opacity: loading ? 0.5 : 1 }}>
          {loading ? '…' : '↻ Refresh'}
        </button>
      </div>

      {/* ─── Stats strip ──────────────────────────────────────────────────────── */}
      {!loading && sensors.length > 0 && (
        <div className="card-grid">
          <div className="card stat-card" style={{ borderLeft: '3px solid #2563eb' }}>
            <div className="stat-value">{sensors.length}</div>
            <div className="stat-label">Sensors Deployed</div>
          </div>
          <div className="card stat-card" style={{ borderLeft: '3px solid #7c3aed' }}>
            <div className="stat-value">{totalSubsystems}</div>
            <div className="stat-label">Active Subsystems</div>
          </div>
          <div className="card stat-card" style={{ borderLeft: '3px solid #059669' }}>
            <div className="stat-value">{natsCount}</div>
            <div className="stat-label">NATS Transports</div>
          </div>
          <div className="card stat-card" style={{ borderLeft: '3px solid #ea580c' }}>
            <div className="stat-value">{totalConfigKeys}</div>
            <div className="stat-label">Config Keys Total</div>
          </div>
        </div>
      )}

      {/* ─── Search ───────────────────────────────────────────────────────────── */}
      {!loading && sensors.length > 0 && (
        <div className="filter-bar" style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <span style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: '#475569', pointerEvents: 'none' }}>🔍</span>
            <input
              type="text"
              placeholder="Search sensors, subsystems, or descriptions…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: '2.25rem', width: '100%', boxSizing: 'border-box' }}
            />
          </div>
          {search && (
            <button className="btn-secondary" onClick={() => setSearch('')} style={{ fontSize: '0.8125rem', whiteSpace: 'nowrap' }}>
              Clear
            </button>
          )}
          {search && filteredSensors.length > 0 && (
            <span style={{ fontSize: '0.8125rem', color: '#64748b', whiteSpace: 'nowrap' }}>
              {filteredSensors.length} of {sensors.length}
            </span>
          )}
        </div>
      )}

      {/* ─── Error ────────────────────────────────────────────────────────────── */}
      {error && (
        <div className="error-msg" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>⚠️ {error}</span>
          <button onClick={load} style={{ background: 'none', border: 'none', color: '#fca5a5', cursor: 'pointer', fontWeight: 600, textDecoration: 'underline', fontSize: '0.875rem' }}>
            Retry
          </button>
        </div>
      )}

      {/* ─── Loading skeletons ─────────────────────────────────────────────────── */}
      {loading && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {[0, 1, 2].map((i) => (
            <div key={i} className="card loading-skeleton" style={{ height: '10rem' }} />
          ))}
        </div>
      )}

      {/* ─── Empty state ──────────────────────────────────────────────────────── */}
      {!loading && sensors.length === 0 && !error && (
        <div className="card empty-state" style={{ padding: '4rem' }}>
          <div style={{ fontSize: '3rem', marginBottom: '0.75rem' }}>🔬</div>
          <div style={{ color: '#94a3b8', fontWeight: 600, marginBottom: '0.25rem' }}>No sensors available</div>
          <div style={{ color: '#475569', fontSize: '0.875rem' }}>Start a sensor adapter to see it here.</div>
        </div>
      )}

      {/* ─── No search results ────────────────────────────────────────────────── */}
      {!loading && sensors.length > 0 && filteredSensors.length === 0 && (
        <div className="card empty-state">
          <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🔍</div>
          <div style={{ color: '#94a3b8', fontWeight: 600, marginBottom: '0.5rem' }}>No sensors match "{search}"</div>
          <button onClick={() => setSearch('')} style={{ background: 'none', border: 'none', color: '#60a5fa', cursor: 'pointer', fontSize: '0.875rem', textDecoration: 'underline' }}>
            Clear search
          </button>
        </div>
      )}

      {/* ─── Sensor cards ─────────────────────────────────────────────────────── */}
      {!loading && filteredSensors.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {filteredSensors.map((sensor) => (
            <SensorCard key={sensor.id} sensor={sensor} highlight={search} />
          ))}
        </div>
      )}
    </div>
  );
}
