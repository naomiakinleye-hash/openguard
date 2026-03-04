import { useEffect, useState } from 'react';
import { api, type SensorInfo } from '../api';

const SENSOR_ICONS: Record<string, string> = {
  hostguard: '🖥️',
  agentguard: '🤖',
  commsguard: '📡',
};

function ConfigTable({ config }: { config: Record<string, unknown> }) {
  return (
    <table>
      <thead>
        <tr>
          <th>Key</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        {Object.entries(config).map(([key, value]) => (
          <tr key={key}>
            <td><code>{key}</code></td>
            <td>
              {Array.isArray(value) ? (
                <ul style={{ margin: 0, paddingLeft: '1.25rem', listStyle: 'disc' }}>
                  {(value as unknown[]).map((v, i) => (
                    <li key={i} style={{ fontSize: '0.8125rem', color: '#94a3b8' }}>{String(v)}</li>
                  ))}
                </ul>
              ) : (
                <code style={{ color: '#a3e635' }}>{String(value)}</code>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SensorCard({ sensor }: { sensor: SensorInfo }) {
  const [showConfig, setShowConfig] = useState(false);

  return (
    <div className="card" style={{ marginBottom: '1.5rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
        <span style={{ fontSize: '1.5rem' }}>{SENSOR_ICONS[sensor.id] ?? '🔍'}</span>
        <div>
          <h3 style={{ margin: 0, color: '#f1f5f9', fontSize: '1rem' }}>{sensor.name}</h3>
          <span style={{ fontSize: '0.8125rem', color: '#64748b' }}>
            Listen: <code style={{ color: '#94a3b8' }}>{sensor.listen_addr}</code>
          </span>
        </div>
      </div>

      <p style={{ margin: '0 0 1rem', color: '#94a3b8', fontSize: '0.875rem' }}>
        {sensor.description}
      </p>

      <div style={{ marginBottom: '1rem' }}>
        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>
          Subsystems / Channels
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
          {sensor.subsystems.map((sub) => (
            <span
              key={sub}
              style={{
                display: 'inline-block',
                padding: '0.2rem 0.6rem',
                background: '#0f172a',
                border: '1px solid #334155',
                borderRadius: '9999px',
                fontSize: '0.75rem',
                color: '#60a5fa',
              }}
            >
              {sub.replace(/_/g, ' ')}
            </span>
          ))}
        </div>
      </div>

      <button
        onClick={() => setShowConfig((v) => !v)}
        style={{
          background: '#1e40af',
          color: '#bfdbfe',
          border: 'none',
          borderRadius: '6px',
          padding: '0.375rem 0.875rem',
          cursor: 'pointer',
          fontSize: '0.8125rem',
        }}
      >
        {showConfig ? 'Hide Configuration' : 'Show Configuration'}
      </button>

      {showConfig && (
        <div style={{ marginTop: '1rem' }}>
          <div className="table-card">
            <div className="table-header" style={{ fontSize: '0.8125rem' }}>
              Default Configuration
            </div>
            <ConfigTable config={sensor.config} />
          </div>
        </div>
      )}
    </div>
  );
}

export default function Sensors() {
  const [sensors, setSensors] = useState<SensorInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    api.sensors()
      .then((res) => setSensors(res.sensors))
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      )
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <div className="page-header">
        <h2>Sensors</h2>
        <p>OpenGuard sensor adapters — implementations and default configurations</p>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      {loading ? (
        <div className="loading">Loading…</div>
      ) : sensors.length === 0 ? (
        <div className="empty-state">No sensor data available.</div>
      ) : (
        sensors.map((sensor) => <SensorCard key={sensor.id} sensor={sensor} />)
      )}
    </div>
  );
}
