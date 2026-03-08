import { useCallback, useEffect, useRef, useState } from 'react';
import { api, type ModelProvider } from '../api';
import { useToast } from '../contexts/ToastContext';

const PROVIDER_SIGN_IN_LABELS: Record<string, string> = {
  'google-gemini': 'Sign in with Google',
};

export default function ModelSettings() {
  const [providers, setProviders] = useState<ModelProvider[]>([]);
  const [active, setActive] = useState('');
  const [selected, setSelected] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  // Inline credential-entry form state (for non-OAuth2 providers)
  const [keyProvider, setKeyProvider] = useState('');
  const [keyInput, setKeyInput] = useState('');
  const [keySaving, setKeySaving] = useState(false);

  const { addToast } = useToast();
  const popupRef = useRef<Window | null>(null);

  const loadProviders = useCallback(() => {
    api.models()
      .then((res) => {
        setProviders(res.providers);
        setActive(res.active);
        setSelected((prev) => prev || res.active);
      })
      .catch((err: unknown) =>
        setError(err instanceof Error ? err.message : String(err)),
      )
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { loadProviders(); }, [loadProviders]);

  // Listen for the postMessage sent by the OAuth2 callback popup page.
  useEffect(() => {
    function handleMessage(event: MessageEvent) {
      if (event.data?.type !== 'og-oauth-result') return;
      if (popupRef.current) {
        popupRef.current.close();
        popupRef.current = null;
      }
      if (event.data.success) {
        addToast(`Connected to ${String(event.data.provider)}`, 'success');
        loadProviders();
      } else {
        addToast(
          `Sign-in failed: ${String(event.data.error ?? 'unknown error')}`,
          'error',
        );
      }
    }
    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, [addToast, loadProviders]);

  async function handleOAuthConnect(provider: string) {
    try {
      const { auth_url } = await api.oauthStart(provider);
      const popup = window.open(
        auth_url,
        'openguard-oauth',
        'width=520,height=700,noopener=no,noreferrer=no',
      );
      if (popup) {
        popupRef.current = popup;
      } else {
        addToast('Popup blocked — please allow popups for this site.', 'error');
      }
    } catch (err) {
      addToast(err instanceof Error ? err.message : 'Failed to start sign-in', 'error');
    }
  }

  function handleKeyConnect() {
    if (!keyInput.trim()) return;
    setKeySaving(true);
    api.saveCredential(keyProvider, keyInput.trim())
      .then(() => {
        addToast(`Connected to ${keyProvider}`, 'success');
        setKeyProvider('');
        setKeyInput('');
        loadProviders();
      })
      .catch((err: unknown) =>
        addToast(err instanceof Error ? err.message : 'Save failed', 'error'),
      )
      .finally(() => setKeySaving(false));
  }

  function handleDisconnect(provider: string) {
    api.deleteCredential(provider)
      .then(() => {
        addToast(`Disconnected from ${provider}`, 'success');
        // If we just disconnected the active provider, deselect it.
        if (selected === provider) setSelected('');
        loadProviders();
      })
      .catch((err: unknown) =>
        addToast(err instanceof Error ? err.message : 'Disconnect failed', 'error'),
      );
  }

  function handleSave() {
    if (selected === active) return;
    setSaving(true);
    api.setActiveModel(selected)
      .then((res) => {
        setActive(res.active);
        addToast(`Active provider set to ${res.active}`, 'success');
      })
      .catch((err: unknown) =>
        addToast(err instanceof Error ? err.message : String(err), 'error'),
      )
      .finally(() => setSaving(false));
  }

  return (
    <div>
      <div className="page-header">
        <h2>AI Models</h2>
        <p>Sign in to a model provider and select it as the active AI for OpenGuard analysis</p>
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
              <div
                key={p.id}
                className="card"
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                  border: selected === p.id ? '2px solid #3b82f6' : undefined,
                }}
              >
                {/* Header row */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <input
                    type="radio"
                    name="provider"
                    value={p.id}
                    checked={selected === p.id}
                    disabled={!p.available}
                    onChange={() => setSelected(p.id)}
                    style={{ cursor: p.available ? 'pointer' : 'not-allowed' }}
                  />
                  <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{p.name}</span>
                  {active === p.id && (
                    <span
                      className="badge"
                      style={{ background: '#1d4ed8', color: '#bfdbfe', marginLeft: 'auto' }}
                    >
                      Active
                    </span>
                  )}
                </div>

                <code style={{ fontSize: '0.75rem', color: '#64748b' }}>{p.id}</code>

                {/* Connection section */}
                {p.available ? (
                  /* ── Connected ── */
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span className="badge badge-ok">✓ Connected</span>
                    <button
                      className="btn-secondary"
                      style={{ fontSize: '0.75rem', padding: '0.2rem 0.6rem', marginLeft: 'auto' }}
                      onClick={() => handleDisconnect(p.id)}
                    >
                      Disconnect
                    </button>
                  </div>
                ) : p.uses_oauth ? (
                  /* ── OAuth2 sign-in button ── */
                  <button
                    className="btn-secondary"
                    style={{ fontSize: '0.8rem', padding: '0.375rem 0.75rem' }}
                    onClick={() => void handleOAuthConnect(p.id)}
                  >
                    {PROVIDER_SIGN_IN_LABELS[p.id] ?? `Sign in with ${p.name}`}
                  </button>
                ) : keyProvider === p.id ? (
                  /* ── Inline API key form ── */
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <input
                      type="password"
                      placeholder="Paste your API key…"
                      value={keyInput}
                      autoFocus
                      onChange={(e) => setKeyInput(e.target.value)}
                      onKeyDown={(e) => { if (e.key === 'Enter') handleKeyConnect(); }}
                      style={{
                        background: '#1e293b',
                        border: '1px solid #334155',
                        borderRadius: '6px',
                        padding: '0.4rem 0.75rem',
                        color: '#f1f5f9',
                        fontSize: '0.8rem',
                        outline: 'none',
                      }}
                    />
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button
                        className="btn-secondary"
                        style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem' }}
                        onClick={handleKeyConnect}
                        disabled={keySaving || !keyInput.trim()}
                      >
                        {keySaving ? 'Saving…' : 'Save'}
                      </button>
                      <button
                        className="btn-secondary"
                        style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem' }}
                        onClick={() => { setKeyProvider(''); setKeyInput(''); }}
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  /* ── Connect button (opens API key form) ── */
                  <button
                    className="btn-secondary"
                    style={{ fontSize: '0.8rem', padding: '0.375rem 0.75rem' }}
                    onClick={() => { setKeyProvider(p.id); setKeyInput(''); }}
                  >
                    Connect
                  </button>
                )}
              </div>
            ))}
          </div>

          <button
            onClick={handleSave}
            disabled={saving || selected === active || !selected}
            style={{
              marginTop: '1.5rem',
              background: '#1d4ed8',
              color: '#fff',
              border: 'none',
              borderRadius: '6px',
              padding: '0.5rem 1.25rem',
              fontSize: '0.875rem',
              fontWeight: 600,
              cursor: saving || selected === active || !selected ? 'not-allowed' : 'pointer',
              opacity: saving || selected === active || !selected ? 0.6 : 1,
            }}
          >
            {saving ? 'Saving…' : 'Set Active Provider'}
          </button>
        </>
      )}
    </div>
  );
}
