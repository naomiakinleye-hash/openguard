import { useEffect, useState } from 'react';
import { api, type WebhookConfig } from '../api';
import { useToast } from '../contexts/ToastContext';

const FORMATS = ['generic', 'slack', 'pagerduty'] as const;
type Format = typeof FORMATS[number];

const TIER_LABELS: Record<number, string> = { 0: 'T0+', 1: 'T1+', 2: 'T2+', 3: 'T3+', 4: 'T4 only' };

const defaultWh = (): Omit<WebhookConfig, 'id' | 'created_at'> => ({
  name: '', url: '', min_tier: 2, format: 'generic', enabled: true,
});

export default function WebhookSettings() {
  const { addToast } = useToast();
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [form, setForm] = useState(defaultWh());
  const [saving, setSaving] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  async function load() {
    try {
      const res = await api.listWebhooks();
      setWebhooks(res.webhooks);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
    } finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!form.name || !form.url) return;
    setCreating(true);
    try {
      await api.createWebhook(form);
      addToast(`Webhook "${form.name}" created`, 'success');
      setForm(defaultWh());
      await load();
    } catch (err: unknown) {
      addToast(`Create failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally { setCreating(false); }
  }

  async function handleToggle(wh: WebhookConfig) {
    setSaving(wh.id);
    try {
      await api.updateWebhook(wh.id, { enabled: !wh.enabled });
      addToast(`Webhook ${wh.enabled ? 'disabled' : 'enabled'}`, 'success');
      await load();
    } catch (err: unknown) {
      addToast(`Update failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally { setSaving(null); }
  }

  async function handleDelete(wh: WebhookConfig) {
    if (!confirm(`Delete webhook "${wh.name}"?`)) return;
    try {
      await api.deleteWebhook(wh.id);
      addToast(`Webhook "${wh.name}" deleted`, 'success');
      await load();
    } catch (err: unknown) {
      addToast(`Delete failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    }
  }

  return (
    <div>
      <div className="page-header">
        <h2>Webhook Settings</h2>
        <p>Configure outbound alert webhooks for incident notifications.</p>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      {/* Create webhook form */}
      <div className="card" style={{ marginBottom: '1.5rem', maxWidth: '700px' }}>
        <h3 style={{ margin: '0 0 1rem' }}>Add Webhook</h3>
        <form onSubmit={handleCreate} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div style={{ flex: 1, minWidth: '180px', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Name</label>
              <input
                className="input-field"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="My Slack Alert"
                required
              />
            </div>
            <div style={{ flex: 2, minWidth: '280px', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Webhook URL</label>
              <input
                className="input-field"
                value={form.url}
                onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
                placeholder="https://hooks.slack.com/…"
                required
              />
            </div>
          </div>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Minimum tier</label>
              <select
                className="input-field"
                value={form.min_tier}
                onChange={(e) => setForm((f) => ({ ...f, min_tier: Number(e.target.value) }))}
              >
                {[0, 1, 2, 3, 4].map((t) => <option key={t} value={t}>{TIER_LABELS[t]}</option>)}
              </select>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
              <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Format</label>
              <select
                className="input-field"
                value={form.format}
                onChange={(e) => setForm((f) => ({ ...f, format: e.target.value as Format }))}
              >
                {FORMATS.map((fmt) => <option key={fmt} value={fmt}>{fmt}</option>)}
              </select>
            </div>
            <button className="btn-approve" type="submit" disabled={creating}>
              {creating ? '…' : '+ Add'}
            </button>
          </div>
        </form>
      </div>

      {/* Webhook list */}
      {loading ? <div className="loading">Loading…</div> : webhooks.length === 0 ? (
        <div className="empty-state">No webhooks configured. Add one above to start receiving alerts.</div>
      ) : (
        <div className="card" style={{ padding: 0 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>URL</th>
                <th>Min Tier</th>
                <th>Format</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {webhooks.map((wh) => (
                <tr key={wh.id} style={{ opacity: wh.enabled ? 1 : 0.55 }}>
                  <td><strong>{wh.name}</strong></td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.8rem', maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {wh.url}
                  </td>
                  <td><span className={`badge badge-t${wh.min_tier}`}>{TIER_LABELS[wh.min_tier]}</span></td>
                  <td>{wh.format}</td>
                  <td>
                    <span style={{ color: wh.enabled ? 'var(--success)' : 'var(--text-muted)' }}>
                      {wh.enabled ? '● Active' : '○ Disabled'}
                    </span>
                  </td>
                  <td style={{ display: 'flex', gap: '0.5rem' }}>
                    <button
                      className={wh.enabled ? 'btn-deny' : 'btn-approve'}
                      style={{ fontSize: '0.8rem', padding: '0.3rem 0.75rem' }}
                      disabled={saving === wh.id}
                      onClick={() => handleToggle(wh)}
                    >
                      {saving === wh.id ? '…' : wh.enabled ? 'Disable' : 'Enable'}
                    </button>
                    <button
                      className="btn-deny"
                      style={{ fontSize: '0.8rem', padding: '0.3rem 0.75rem' }}
                      onClick={() => handleDelete(wh)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
