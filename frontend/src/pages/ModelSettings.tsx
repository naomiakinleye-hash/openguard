import { useEffect, useState } from 'react';
import { api, type ModelProvider } from '../api';
import { useToast } from '../contexts/ToastContext';

export default function ModelSettings() {
  const [providers, setProviders] = useState<ModelProvider[]>([]);
  const [active, setActive] = useState('');
  const [selected, setSelected] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const { addToast } = useToast();

  useEffect(() => {
    api.models()
      .then((res) => {
        setProviders(res.providers);
        setActive(res.active);
        setSelected(res.active);
      })
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      )
      .finally(() => setLoading(false));
  }, []);

  function handleSave() {
    if (selected === active) return;
    setSaving(true);
    api.setActiveModel(selected)
      .then((res) => {
        setActive(res.active);
        addToast(`Provider switched to ${res.active}`, 'success');
      })
      .catch((err: unknown) => {
        addToast(
          err instanceof Error ? err.message : String(err),
          'error',
        );
      })
      .finally(() => setSaving(false));
  }

  return (
    <div>
      <div className="page-header">
        <h2>AI Models</h2>
        <p>Select the active AI model provider for OpenGuard analysis</p>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      {loading ? (
        <div className="loading">Loading…</div>
      ) : providers.length === 0 ? (
        <div className="empty-state">No providers available.</div>
      ) : (
        <>
          <div className="card-grid">
            {providers.map((p) => (
              <label
                key={p.id}
                className="card"
                style={{
                  cursor: p.available ? 'pointer' : 'not-allowed',
                  opacity: p.available ? 1 : 0.5,
                  border: selected === p.id ? '2px solid #3b82f6' : undefined,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.5rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <input
                    type="radio"
                    name="provider"
                    value={p.id}
                    checked={selected === p.id}
                    disabled={!p.available}
                    onChange={() => setSelected(p.id)}
                  />
                  <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{p.name}</span>
                </div>
                <code style={{ fontSize: '0.75rem', color: '#64748b' }}>{p.id}</code>
                {p.available ? (
                  <span className="badge badge-ok">API key set</span>
                ) : (
                  <span className="badge badge-error">No API key</span>
                )}
                {active === p.id && (
                  <span className="badge" style={{ background: '#1d4ed8', color: '#bfdbfe' }}>
                    Active
                  </span>
                )}
              </label>
            ))}
          </div>

          <button
            onClick={handleSave}
            disabled={saving || selected === active}
            style={{
              background: '#1d4ed8',
              color: '#fff',
              border: 'none',
              borderRadius: '6px',
              padding: '0.5rem 1.25rem',
              fontSize: '0.875rem',
              fontWeight: 600,
              cursor: saving || selected === active ? 'not-allowed' : 'pointer',
            }}
          >
            {saving ? 'Saving…' : 'Save'}
          </button>
        </>
      )}
    </div>
  );
}
