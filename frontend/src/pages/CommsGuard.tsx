import { useCallback, useEffect, useState } from 'react';
import {
  api,
  type CommsChannel,
  type CommsStatsResponse,
  type CommsEventsResponse,
  type CommsConfigResponse,
  type CommsChannelConfigItem,
  type Event,
} from '../api';
import { useInterval } from '../hooks/useInterval';
import { useToast } from '../contexts/ToastContext';
import Pagination from '../components/Pagination';

// ─── Constants ────────────────────────────────────────────────────────────────

const PAGE_SIZE = 25;

const TIER_COLORS: Record<number, string> = {
  0: '#334155',
  1: '#1d4ed8',
  2: '#d97706',
  3: '#ea580c',
  4: '#dc2626',
};

const EVENT_TYPE_COLORS: Record<string, string> = {
  phishing_detected: '#dc2626',
  credential_harvesting_detected: '#ea580c',
  data_exfiltration_detected: '#b91c1c',
  social_engineering_detected: '#d97706',
  bulk_message_detected: '#ca8a04',
  suspicious_link_detected: '#7c3aed',
  malware_attachment_detected: '#be185d',
  account_takeover_attempt: '#dc2626',
  spam_detected: '#64748b',
  message_received: '#16a34a',
  unknown: '#475569',
};

const CHANNEL_FILTER_OPTIONS = [
  { value: '', label: 'All Channels' },
  { value: 'whatsapp', label: 'WhatsApp' },
  { value: 'telegram', label: 'Telegram' },
  { value: 'messenger', label: 'Messenger' },
  { value: 'twilio_sms', label: 'Twilio SMS' },
  { value: 'twilio_voice', label: 'Twilio Voice' },
  { value: 'twitter', label: 'Twitter / X' },
];

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <div className="card stat-card">
      <div className="stat-value" style={color ? { color } : undefined}>
        {value}
      </div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function ThreatBar({ label, count, max, color }: { label: string; count: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((count / max) * 100) : 0;
  return (
    <div style={{ marginBottom: '0.625rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8125rem', marginBottom: '0.25rem' }}>
        <span style={{ color: '#cbd5e1', textTransform: 'capitalize' }}>
          {label.replace(/_/g, ' ')}
        </span>
        <span style={{ color: '#94a3b8' }}>{count}</span>
      </div>
      <div style={{ background: '#0f172a', borderRadius: '4px', height: '8px', overflow: 'hidden' }}>
        <div
          style={{
            height: '100%',
            borderRadius: '4px',
            width: `${pct}%`,
            background: color,
            transition: 'width 0.5s ease',
          }}
        />
      </div>
    </div>
  );
}

function ChannelCard({
  channel,
  onConfigure,
}: {
  channel: CommsChannel;
  onConfigure: (ch: CommsChannel) => void;
}) {
  const hasActivity = (channel.message_count ?? 0) > 0;
  const hasThreat = (channel.threat_count ?? 0) > 0;

  return (
    <div
      className="card"
      style={{
        borderLeft: `3px solid ${
          hasThreat ? '#dc2626' : channel.configured ? '#16a34a' : '#334155'
        }`,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <span style={{ fontSize: '1.25rem' }}>{channel.icon}</span>
          <span style={{ color: '#f1f5f9', fontWeight: 600, fontSize: '0.9375rem' }}>{channel.name}</span>
        </div>
        <span
          style={{
            fontSize: '0.6875rem',
            fontWeight: 700,
            padding: '0.15rem 0.5rem',
            borderRadius: '9999px',
            background: channel.configured ? '#14532d' : '#1e293b',
            color: channel.configured ? '#86efac' : '#64748b',
            border: `1px solid ${channel.configured ? '#166534' : '#334155'}`,
          }}
        >
          {channel.configured ? 'CONFIGURED' : 'NOT CONFIGURED'}
        </span>
      </div>

      <p style={{ fontSize: '0.8125rem', color: '#64748b', margin: '0 0 0.75rem' }}>
        {channel.description}
      </p>

      <div style={{ display: 'flex', gap: '1.5rem', marginBottom: '0.875rem' }}>
        <div>
          <div style={{ fontSize: '1.125rem', fontWeight: 700, color: '#f1f5f9' }}>
            {channel.message_count ?? 0}
          </div>
          <div style={{ fontSize: '0.6875rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Messages
          </div>
        </div>
        <div>
          <div
            style={{
              fontSize: '1.125rem',
              fontWeight: 700,
              color: hasThreat ? '#f87171' : '#94a3b8',
            }}
          >
            {channel.threat_count ?? 0}
          </div>
          <div style={{ fontSize: '0.6875rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Threats
          </div>
        </div>
        {channel.last_event && (
          <div>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
              {new Date(channel.last_event).toLocaleTimeString()}
            </div>
            <div style={{ fontSize: '0.6875rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Last Event
            </div>
          </div>
        )}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <code style={{ fontSize: '0.75rem', color: '#475569', flex: 1 }}>
          {channel.webhook_path}
        </code>
        <button
          onClick={() => onConfigure(channel)}
          style={{
            background: '#1e3a5f',
            color: '#93c5fd',
            border: '1px solid #1e40af',
            borderRadius: '6px',
            padding: '0.3rem 0.75rem',
            cursor: 'pointer',
            fontSize: '0.75rem',
            whiteSpace: 'nowrap',
          }}
        >
          ⚙️ Configure
        </button>
      </div>

      {hasActivity && hasThreat && (
        <div
          style={{
            marginTop: '0.625rem',
            padding: '0.375rem 0.625rem',
            background: '#450a0a',
            border: '1px solid #7f1d1d',
            borderRadius: '6px',
            fontSize: '0.75rem',
            color: '#fca5a5',
            display: 'flex',
            alignItems: 'center',
            gap: '0.375rem',
          }}
        >
          ⚠️ Threat activity detected on this channel — review events below.
        </div>
      )}
    </div>
  );
}

// ─── Configuration Modal ──────────────────────────────────────────────────────

interface ConfigModalProps {
  channel: CommsChannel;
  configItem: CommsChannelConfigItem | undefined;
  onClose: () => void;
  onSaved: () => void;
}

function ConfigModal({ channel, configItem, onClose, onSaved }: ConfigModalProps) {
  const { addToast } = useToast();
  const [enabled, setEnabled] = useState(configItem?.enabled ?? false);
  const [secret, setSecret] = useState('');
  const [verifyToken, setVerifyToken] = useState('');
  const [accountSID, setAccountSID] = useState('');
  const [bearerToken, setBearerToken] = useState('');
  const [botToken, setBotToken] = useState('');
  const [webhookURL, setWebhookURL] = useState(configItem?.webhook_url ?? '');
  const [saving, setSaving] = useState(false);

  async function handleSave() {
    setSaving(true);
    try {
      await api.updateCommsChannel({
        id: channel.id,
        enabled,
        webhook_secret: secret || undefined,
        verify_token: verifyToken || undefined,
        account_sid: accountSID || undefined,
        bearer_token: bearerToken || undefined,
        bot_token: botToken || undefined,
        webhook_url: webhookURL || undefined,
      });
      addToast(`${channel.name} configuration saved`, 'success');
      onSaved();
      onClose();
    } catch (err: unknown) {
      addToast(`Save failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    } finally {
      setSaving(false);
    }
  }

  const showWebhookSecret = ['whatsapp', 'messenger', 'twitter'].includes(channel.id);
  const showVerifyToken = ['whatsapp', 'messenger'].includes(channel.id);
  const showBotToken = channel.id === 'telegram';
  const showAccountSID = ['twilio_sms', 'twilio_voice'].includes(channel.id);
  const showBearerToken = ['twitter', 'twilio_sms', 'twilio_voice'].includes(channel.id);

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.7)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 100,
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        className="card"
        style={{ width: '440px', maxWidth: '95vw', maxHeight: '90vh', overflowY: 'auto' }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
          <h3 style={{ margin: 0, color: '#f1f5f9' }}>
            {channel.icon} Configure {channel.name}
          </h3>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: '1.25rem' }}
          >
            ✕
          </button>
        </div>

        <p style={{ fontSize: '0.8125rem', color: '#64748b', marginBottom: '1rem' }}>
          {channel.description}
        </p>

        <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            style={{ width: '1rem', height: '1rem', accentColor: '#3b82f6' }}
          />
          <span style={{ color: '#cbd5e1', fontSize: '0.875rem' }}>Enable this channel</span>
        </label>

        {showWebhookSecret && (
          <div style={{ marginBottom: '0.875rem' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#64748b', marginBottom: '0.35rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              App / Webhook Secret {configItem?.has_webhook_secret && <span style={{ color: '#16a34a' }}>✓ set</span>}
            </label>
            <input
              type="password"
              placeholder={configItem?.has_webhook_secret ? '(unchanged)' : 'Enter secret…'}
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              style={{ width: '100%', boxSizing: 'border-box' }}
            />
          </div>
        )}

        {showVerifyToken && (
          <div style={{ marginBottom: '0.875rem' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#64748b', marginBottom: '0.35rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Verify Token {configItem?.has_verify_token && <span style={{ color: '#16a34a' }}>✓ set</span>}
            </label>
            <input
              type="password"
              placeholder={configItem?.has_verify_token ? '(unchanged)' : 'Enter verify token…'}
              value={verifyToken}
              onChange={(e) => setVerifyToken(e.target.value)}
              style={{ width: '100%', boxSizing: 'border-box' }}
            />
          </div>
        )}

        {showBotToken && (
          <div style={{ marginBottom: '0.875rem' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#64748b', marginBottom: '0.35rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Bot Token {configItem?.has_bot_token && <span style={{ color: '#16a34a' }}>✓ set</span>}
            </label>
            <input
              type="password"
              placeholder={configItem?.has_bot_token ? '(unchanged)' : 'Enter bot token…'}
              value={botToken}
              onChange={(e) => setBotToken(e.target.value)}
              style={{ width: '100%', boxSizing: 'border-box' }}
            />
          </div>
        )}

        {showAccountSID && (
          <div style={{ marginBottom: '0.875rem' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#64748b', marginBottom: '0.35rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Account SID {configItem?.has_account_sid && <span style={{ color: '#16a34a' }}>✓ set</span>}
            </label>
            <input
              type="text"
              placeholder={configItem?.has_account_sid ? '(unchanged)' : 'AC…'}
              value={accountSID}
              onChange={(e) => setAccountSID(e.target.value)}
              style={{ width: '100%', boxSizing: 'border-box' }}
            />
          </div>
        )}

        {showBearerToken && (
          <div style={{ marginBottom: '0.875rem' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#64748b', marginBottom: '0.35rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Auth Token / Bearer Token {configItem?.has_bearer_token && <span style={{ color: '#16a34a' }}>✓ set</span>}
            </label>
            <input
              type="password"
              placeholder={configItem?.has_bearer_token ? '(unchanged)' : 'Enter token…'}
              value={bearerToken}
              onChange={(e) => setBearerToken(e.target.value)}
              style={{ width: '100%', boxSizing: 'border-box' }}
            />
          </div>
        )}

        <div style={{ marginBottom: '1.25rem' }}>
          <label style={{ display: 'block', fontSize: '0.75rem', color: '#64748b', marginBottom: '0.35rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Webhook URL (public endpoint to register with provider)
          </label>
          <input
            type="url"
            placeholder="https://openguard.example.com"
            value={webhookURL}
            onChange={(e) => setWebhookURL(e.target.value)}
            style={{ width: '100%', boxSizing: 'border-box' }}
          />
          {webhookURL && (
            <code style={{ fontSize: '0.75rem', color: '#475569', display: 'block', marginTop: '0.35rem' }}>
              Full webhook: {webhookURL}{channel.webhook_path}
            </code>
          )}
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
          <button className="btn-secondary" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            style={{
              background: '#1e40af',
              color: '#bfdbfe',
              border: 'none',
              borderRadius: '6px',
              padding: '0.5rem 1.25rem',
              cursor: saving ? 'not-allowed' : 'pointer',
              fontSize: '0.875rem',
              fontWeight: 600,
            }}
          >
            {saving ? 'Saving…' : 'Save Configuration'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Events Table ─────────────────────────────────────────────────────────────

function CommsEventsTable({
  channelFilter,
  onChannelChange,
}: {
  channelFilter: string;
  onChannelChange: (ch: string) => void;
}) {
  const [page, setPage] = useState(1);
  const [data, setData] = useState<CommsEventsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchEvents = useCallback(() => {
    setLoading(true);
    api
      .commsEvents(channelFilter || undefined, page)
      .then(setData)
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, [channelFilter, page]);

  useEffect(() => { setPage(1); }, [channelFilter]);
  useEffect(() => { fetchEvents(); }, [fetchEvents]);
  useInterval(fetchEvents, 15000);

  const events: Event[] = data?.events ?? [];
  const total = data?.total ?? 0;

  function getEventChannel(ev: Event): string {
    if (ev.source && typeof ev.source === 'object') {
      const src = ev.source as Record<string, unknown>;
      if (src.adapter) return String(src.adapter);
    }
    const meta = ev.metadata as Record<string, unknown> | undefined;
    if (meta?.channel) return String(meta.channel);
    return '—';
  }

  function getEventType(ev: Event): string {
    const meta = ev.metadata as Record<string, unknown> | undefined;
    if (meta?.event_type) return String(meta.event_type);
    return ev.type ?? '—';
  }

  function getIndicators(ev: Event): string[] {
    if (Array.isArray(ev.indicators)) return ev.indicators as string[];
    return [];
  }

  return (
    <div className="table-card">
      <div className="table-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span>
          Comms Events
          {total > 0 && <span style={{ color: '#64748b', fontWeight: 400, marginLeft: '0.5rem' }}>({total} total)</span>}
        </span>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <select
            value={channelFilter}
            onChange={(e) => onChannelChange(e.target.value)}
            style={{ fontSize: '0.8125rem' }}
          >
            {CHANNEL_FILTER_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          <button className="btn-secondary" onClick={fetchEvents} style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem' }}>
            ↻
          </button>
        </div>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      {loading ? (
        <div className="loading">Loading events…</div>
      ) : events.length === 0 ? (
        <div className="empty-state">No comms events found{channelFilter ? ` for ${channelFilter}` : ''}.</div>
      ) : (
        <>
          <div style={{ overflowX: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Channel</th>
                  <th>Event Type</th>
                  <th>Tier</th>
                  <th>Risk</th>
                  <th>Sender</th>
                  <th>Indicators</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev, i) => {
                  const evType = getEventType(ev);
                  const channel = getEventChannel(ev);
                  const indicators = getIndicators(ev);
                  const tier = ev.tier as number | undefined;
                  const meta = ev.metadata as Record<string, unknown> | undefined;
                  const sender = meta?.sender_id ? String(meta.sender_id) : '—';
                  return (
                    <tr key={ev.id ?? i}>
                      <td style={{ whiteSpace: 'nowrap', fontSize: '0.75rem', color: '#94a3b8' }}>
                        {ev.timestamp ? new Date(String(ev.timestamp)).toLocaleString() : '—'}
                      </td>
                      <td>
                        <span style={{ fontSize: '0.75rem', color: '#60a5fa' }}>
                          {channel}
                        </span>
                      </td>
                      <td>
                        <span
                          style={{
                            fontSize: '0.7rem',
                            padding: '0.125rem 0.5rem',
                            borderRadius: '9999px',
                            background: '#0f172a',
                            color: EVENT_TYPE_COLORS[evType] ?? EVENT_TYPE_COLORS.unknown,
                            border: `1px solid ${EVENT_TYPE_COLORS[evType] ?? EVENT_TYPE_COLORS.unknown}40`,
                          }}
                        >
                          {evType.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td>
                        {tier !== undefined ? (
                          <span
                            style={{
                              fontWeight: 700,
                              color: TIER_COLORS[tier] ?? '#94a3b8',
                              fontSize: '0.8125rem',
                            }}
                          >
                            T{tier}
                          </span>
                        ) : '—'}
                      </td>
                      <td style={{ fontSize: '0.8125rem', color: '#94a3b8' }}>
                        {ev.risk_score !== undefined ? Number(ev.risk_score).toFixed(0) : '—'}
                      </td>
                      <td style={{ fontSize: '0.75rem', color: '#94a3b8', maxWidth: '120px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {sender}
                      </td>
                      <td>
                        {indicators.length > 0 ? (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                            {indicators.slice(0, 3).map((ind, j) => (
                              <span
                                key={j}
                                style={{
                                  fontSize: '0.65rem',
                                  padding: '0.1rem 0.4rem',
                                  borderRadius: '9999px',
                                  background: '#450a0a',
                                  color: '#fca5a5',
                                  border: '1px solid #7f1d1d',
                                }}
                              >
                                {ind}
                              </span>
                            ))}
                            {indicators.length > 3 && (
                              <span style={{ fontSize: '0.65rem', color: '#64748b' }}>
                                +{indicators.length - 3}
                              </span>
                            )}
                          </div>
                        ) : (
                          <span style={{ fontSize: '0.75rem', color: '#1e293b' }}>—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <Pagination
            page={page}
            pageSize={PAGE_SIZE}
            total={total}
            onPageChange={setPage}
          />
        </>
      )}
    </div>
  );
}

// ─── Main CommsGuard Page ─────────────────────────────────────────────────────

export default function CommsGuard() {
  const [stats, setStats] = useState<CommsStatsResponse | null>(null);
  const [config, setConfig] = useState<CommsConfigResponse | null>(null);
  const [configLoading, setConfigLoading] = useState(true);
  const [statsLoading, setStatsLoading] = useState(true);
  const [error, setError] = useState('');

  // Channel filter is lifted to share between channel cards and events table.
  const [channelFilter, setChannelFilter] = useState('');

  // Configure modal state.
  const [modalChannel, setModalChannel] = useState<CommsChannel | null>(null);

  const fetchStats = useCallback(() => {
    api
      .commsStats()
      .then(setStats)
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setStatsLoading(false));
  }, []);

  const fetchConfig = useCallback(() => {
    api
      .commsConfig()
      .then(setConfig)
      .catch(() => {/* config failure is non-fatal */})
      .finally(() => setConfigLoading(false));
  }, []);

  useEffect(() => { fetchStats(); fetchConfig(); }, [fetchStats, fetchConfig]);
  useInterval(fetchStats, 20000);

  const channels = stats?.channels ?? [];
  const eventTypes = stats?.event_types ?? [];
  const maxEventTypeCount = eventTypes.reduce((m, e) => Math.max(m, e.count), 1);

  function getConfigItem(id: string): CommsChannelConfigItem | undefined {
    return config?.channels.find((c) => c.id === id);
  }

  function handleOpenModal(ch: CommsChannel) {
    setModalChannel(ch);
  }

  function handleModalClose() {
    setModalChannel(null);
  }

  function handleModalSaved() {
    fetchConfig();
    fetchStats();
  }

  // Threat channel list for the threat overview panel.
  const threatChannels = channels.filter((ch) => (ch.threat_count ?? 0) > 0);

  return (
    <div>
      {/* ── Page Header ─────────────────────────────────────────────────── */}
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
        <div>
          <h2>📡 CommsGuard</h2>
          <p>
            Multi-channel communication threat monitoring — WhatsApp, Telegram, Messenger, Twilio, Twitter/X
          </p>
        </div>
        <button className="btn-secondary" onClick={() => { fetchStats(); fetchConfig(); }}>
          ↻ Refresh
        </button>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      {/* ── Statistics Row ───────────────────────────────────────────────── */}
      {statsLoading ? (
        <div className="loading">Loading statistics…</div>
      ) : (
        <div className="card-grid">
          <StatCard label="Total Comms Events" value={stats?.total_events ?? 0} />
          <StatCard
            label="Threats Detected"
            value={stats?.total_threats ?? 0}
            color={(stats?.total_threats ?? 0) > 0 ? '#f87171' : undefined}
          />
          <StatCard
            label="Channels Monitored"
            value={channels.filter((c) => c.configured).length}
          />
          <StatCard
            label="Active Threat Channels"
            value={threatChannels.length}
            color={threatChannels.length > 0 ? '#fbbf24' : undefined}
          />
        </div>
      )}

      {/* ── Channel Cards Grid ───────────────────────────────────────────── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
          gap: '1rem',
          marginBottom: '1.5rem',
        }}
      >
        {(statsLoading ? [] : channels).map((ch) => (
          <ChannelCard
            key={ch.id}
            channel={ch}
            onConfigure={handleOpenModal}
          />
        ))}
      </div>

      {/* ── Threat Distribution + Global Config ─────────────────────────── */}
      <div className="card-grid">
        {/* Threat event-type breakdown */}
        <div className="card">
          <div className="section-title">Threat Event Type Breakdown</div>
          {eventTypes.length === 0 ? (
            <div style={{ color: '#475569', fontSize: '0.875rem' }}>
              No comms events recorded yet.
            </div>
          ) : (
            eventTypes.map((et) => (
              <ThreatBar
                key={et.type}
                label={et.type}
                count={et.count}
                max={maxEventTypeCount}
                color={EVENT_TYPE_COLORS[et.type] ?? '#64748b'}
              />
            ))
          )}
        </div>

        {/* Global CommsGuard configuration */}
        {!configLoading && config && (
          <div className="card">
            <div className="section-title">Global Settings</div>
            <table>
              <tbody>
                <tr>
                  <td style={{ color: '#64748b', fontSize: '0.8125rem' }}>Content Analysis</td>
                  <td>
                    <span
                      style={{
                        fontSize: '0.75rem',
                        fontWeight: 700,
                        color: config.enable_content_analysis ? '#86efac' : '#f87171',
                      }}
                    >
                      {config.enable_content_analysis ? 'Enabled' : 'Disabled'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td style={{ color: '#64748b', fontSize: '0.8125rem' }}>Bulk Message Threshold</td>
                  <td>
                    <code style={{ color: '#a3e635', fontSize: '0.8125rem' }}>
                      {config.bulk_message_threshold} msgs
                    </code>
                  </td>
                </tr>
                <tr>
                  <td style={{ color: '#64748b', fontSize: '0.8125rem' }}>Bulk Window</td>
                  <td>
                    <code style={{ color: '#a3e635', fontSize: '0.8125rem' }}>
                      {config.bulk_message_window_sec}s
                    </code>
                  </td>
                </tr>
              </tbody>
            </table>

            <div style={{ marginTop: '1.25rem' }}>
              <div className="section-title" style={{ marginBottom: '0.75rem' }}>
                Detection Rules
              </div>
              {[
                { id: 'COMMS-001', name: 'Phishing Detection', tiers: 'T1–T3', active: true },
                { id: 'COMMS-002', name: 'Data Exfiltration', tiers: 'T1–T4', active: true },
              ].map((rule) => (
                <div
                  key={rule.id}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '0.5rem 0.75rem',
                    background: '#0f172a',
                    borderRadius: '6px',
                    marginBottom: '0.5rem',
                    border: '1px solid #1e293b',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '0.8125rem', color: '#f1f5f9' }}>{rule.name}</div>
                    <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                      <code>{rule.id}</code> · tiers {rule.tiers}
                    </div>
                  </div>
                  <span
                    style={{
                      fontSize: '0.65rem',
                      fontWeight: 700,
                      padding: '0.125rem 0.5rem',
                      borderRadius: '9999px',
                      background: '#14532d',
                      color: '#86efac',
                      border: '1px solid #166534',
                    }}
                  >
                    ACTIVE
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Events Table ─────────────────────────────────────────────────── */}
      <CommsEventsTable
        channelFilter={channelFilter}
        onChannelChange={setChannelFilter}
      />

      {/* ── Configuration Modal ──────────────────────────────────────────── */}
      {modalChannel && (
        <ConfigModal
          channel={modalChannel}
          configItem={getConfigItem(modalChannel.id)}
          onClose={handleModalClose}
          onSaved={handleModalSaved}
        />
      )}
    </div>
  );
}
