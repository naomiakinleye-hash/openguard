import { useCallback, useEffect, useState } from 'react';
import {
  api,
  type CommsChannel,
  type CommsStatsResponse,
  type CommsEventsResponse,
  type CommsConfigResponse,
  type CommsChannelConfigItem,
  type CommsGuardConfigResponse,
  type CommsGlobalConfig,
  type CommsChannelConfigPatch,
  type CommsChannelConfigEntry,
  type LinkedDevice,
  type LinkedDevicesResponse,
  type Event,
  type WAStatus,
  type WAQRData,
  type WAMessage,
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
  // Linked device event types
  device_linked: '#16a34a',
  device_unlinked: '#475569',
  suspicious_device_linked: '#dc2626',
  unknown_device_detected: '#ea580c',
  device_session_hijack: '#7c3aed',
  device_alert: '#64748b',
  unknown: '#475569',
};

const CHANNEL_FILTER_OPTIONS = [
  { value: '', label: 'All Channels' },
  { value: 'whatsapp', label: 'WhatsApp' },
  { value: 'whatsapp_linked', label: 'WhatsApp Linked Devices' },
  { value: 'telegram', label: 'Telegram' },
  { value: 'messenger', label: 'Messenger' },
  { value: 'twilio_sms', label: 'Twilio SMS' },
  { value: 'twilio_voice', label: 'Twilio Voice' },
  { value: 'twitter', label: 'Twitter / X' },
];

const CHANNELS_LIST = [
  { id: 'whatsapp',        name: 'WhatsApp',               icon: '📱', fields: ['webhook_secret', 'verify_token', 'webhook_url'] },
  { id: 'whatsapp_linked', name: 'WhatsApp Linked Devices', icon: '📲', fields: ['webhook_secret', 'bearer_token', 'webhook_url'] },
  { id: 'telegram',        name: 'Telegram',               icon: '✈️',  fields: ['bot_token', 'webhook_url'] },
  { id: 'messenger',       name: 'Messenger',              icon: '💬', fields: ['webhook_secret', 'verify_token', 'webhook_url'] },
  { id: 'twilio_sms',      name: 'Twilio SMS',             icon: '📨', fields: ['account_sid', 'bearer_token', 'webhook_url'] },
  { id: 'twilio_voice',    name: 'Twilio Voice',           icon: '📞', fields: ['account_sid', 'bearer_token', 'webhook_url'] },
  { id: 'twitter',         name: 'Twitter / X',            icon: '🐦', fields: ['webhook_secret', 'bearer_token', 'webhook_url'] },
];

// ─── TunnelSetupCard ──────────────────────────────────────────────────────────

const WEBHOOK_PATHS: { id: string; label: string; path: string }[] = [
  { id: 'whatsapp',        label: 'WhatsApp',              path: '/whatsapp/webhook' },
  { id: 'whatsapp_linked', label: 'Linked Devices',        path: '/whatsapp/linked-devices/webhook' },
  { id: 'telegram',        label: 'Telegram',              path: '/telegram/webhook' },
  { id: 'messenger',       label: 'Messenger',             path: '/messenger/webhook' },
  { id: 'twilio_sms',      label: 'Twilio SMS',            path: '/twilio/sms' },
  { id: 'twilio_voice',    label: 'Twilio Voice',          path: '/twilio/voice' },
  { id: 'twitter',         label: 'Twitter/X',             path: '/twitter/webhook' },
];

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  function copy() {
    void navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }
  return (
    <button
      onClick={copy}
      title="Copy"
      style={{
        padding: '0.2rem 0.5rem', borderRadius: '4px', border: '1px solid #334155',
        background: copied ? '#14532d' : '#1e293b', color: copied ? '#4ade80' : '#64748b',
        cursor: 'pointer', fontSize: '0.7rem', fontWeight: 700, flexShrink: 0,
        transition: 'all 0.15s',
      }}
    >
      {copied ? '✓ Copied' : 'Copy'}
    </button>
  );
}

function CodeLine({ code }: { code: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#0f172a', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.5rem 0.75rem' }}>
      <code style={{ flex: 1, fontSize: '0.8125rem', color: '#a3e635', fontFamily: 'monospace', overflowX: 'auto', whiteSpace: 'nowrap' }}>
        {code}
      </code>
      <CopyButton text={code} />
    </div>
  );
}

function TunnelSetupCard() {
  const [activeMode, setActiveMode] = useState<'ngrok' | 'cloudflared'>('ngrok');
  const [baseUrl, setBaseUrl] = useState('');
  const [webhookPort, setWebhookPort] = useState('8090');

  const displayUrl = baseUrl.trimEnd().replace(/\/$/, '') || `<public-url>`;

  const ngrokCmd    = `COMMSGUARD_TUNNEL_MODE=ngrok COMMSGUARD_LISTEN_ADDR=:${webhookPort} ./commsguard-agent`;
  const ngrokCfgCmd = `ngrok config add-authtoken <YOUR_NGROK_TOKEN>`;
  const cfCmd       = `COMMSGUARD_TUNNEL_MODE=cloudflared COMMSGUARD_LISTEN_ADDR=:${webhookPort} ./commsguard-agent`;


  const inputStyle: React.CSSProperties = {
    background: '#0f172a', border: '1px solid #334155', borderRadius: '6px',
    padding: '0.375rem 0.625rem', color: '#f1f5f9', fontSize: '0.8125rem',
    outline: 'none',
  };

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid #334155', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div className="section-title" style={{ marginBottom: '0.25rem' }}>🔗 Tunnel Setup — Local Hosting</div>
          <p style={{ fontSize: '0.75rem', color: '#64748b' }}>
            Expose the webhook server (:<span style={{ color: '#94a3b8' }}>{webhookPort}</span>) to the internet so external platforms can reach it.
            The tunnel URL is printed to the agent log at startup.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexShrink: 0 }}>
          <label style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Webhook Port</label>
          <input
            type="number" min={1024} max={65535}
            value={webhookPort}
            onChange={e => setWebhookPort(e.target.value)}
            style={{ ...inputStyle, width: '5.5rem' }}
          />
        </div>
      </div>

      {/* Mode tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #334155' }}>
        {(['ngrok', 'cloudflared'] as const).map(mode => (
          <button
            key={mode}
            onClick={() => setActiveMode(mode)}
            style={{
              padding: '0.625rem 1.25rem', background: 'none', border: 'none',
              borderBottom: `2px solid ${activeMode === mode ? '#3b82f6' : 'transparent'}`,
              color: activeMode === mode ? '#60a5fa' : '#64748b',
              fontWeight: 600, fontSize: '0.8125rem', cursor: 'pointer',
              marginBottom: '-1px',
            }}
          >
            {mode === 'ngrok' ? '🟠 ngrok' : '🟡 cloudflared'}
          </button>
        ))}
      </div>

      <div style={{ padding: '1rem 1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {activeMode === 'ngrok' && (
          <>
            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '0.375rem 0.75rem', fontSize: '0.75rem', color: '#94a3b8', flexShrink: 0 }}>1</div>
              <div style={{ flex: 1 }}>
                <p style={{ fontSize: '0.8125rem', color: '#f1f5f9', fontWeight: 600, marginBottom: '0.375rem' }}>
                  Create a free account &amp; authenticate
                </p>
                <p style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '0.5rem' }}>
                  Sign up at <code style={{ color: '#60a5fa' }}>dashboard.ngrok.com</code>, copy your auth token, then run:
                </p>
                <CodeLine code={ngrokCfgCmd} />
                <p style={{ fontSize: '0.7rem', color: '#475569', marginTop: '0.375rem' }}>
                  Or pass <code style={{ color: '#a3e635' }}>NGROK_AUTHTOKEN=&lt;token&gt;</code> inline (see step 2).
                </p>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '0.375rem 0.75rem', fontSize: '0.75rem', color: '#94a3b8', flexShrink: 0 }}>2</div>
              <div style={{ flex: 1 }}>
                <p style={{ fontSize: '0.8125rem', color: '#f1f5f9', fontWeight: 600, marginBottom: '0.375rem' }}>
                  Start commsguard-agent with tunnel mode
                </p>
                <CodeLine code={ngrokCmd} />
                <p style={{ fontSize: '0.7rem', color: '#475569', marginTop: '0.375rem' }}>
                  The agent will start ngrok, wait for the public URL, and print it to the log with all webhook paths.
                </p>
              </div>
            </div>
          </>
        )}

        {activeMode === 'cloudflared' && (
          <>
            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '0.375rem 0.75rem', fontSize: '0.75rem', color: '#94a3b8', flexShrink: 0 }}>1</div>
              <div style={{ flex: 1 }}>
                <p style={{ fontSize: '0.8125rem', color: '#f1f5f9', fontWeight: 600, marginBottom: '0.375rem' }}>
                  Install cloudflared — no account needed for quick tunnels
                </p>
                <CodeLine code="# macOS" />
                <CodeLine code="brew install cloudflared" />
                <div style={{ margin: '0.25rem 0' }} />
                <CodeLine code="# Linux (amd64)" />
                <CodeLine code="curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared && chmod +x cloudflared" />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
              <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '0.375rem 0.75rem', fontSize: '0.75rem', color: '#94a3b8', flexShrink: 0 }}>2</div>
              <div style={{ flex: 1 }}>
                <p style={{ fontSize: '0.8125rem', color: '#f1f5f9', fontWeight: 600, marginBottom: '0.375rem' }}>
                  Start commsguard-agent with tunnel mode
                </p>
                <CodeLine code={cfCmd} />
                <p style={{ fontSize: '0.7rem', color: '#475569', marginTop: '0.375rem' }}>
                  A <code style={{ color: '#a3e635' }}>*.trycloudflare.com</code> URL is generated automatically — no account or DNS change required.
                </p>
              </div>
            </div>
          </>
        )}

        {/* Webhook URL generator */}
        <div style={{ borderTop: '1px solid #334155', paddingTop: '1rem' }}>
          <p style={{ fontSize: '0.8125rem', color: '#f1f5f9', fontWeight: 600, marginBottom: '0.625rem' }}>
            3 · Register webhook URLs in each platform's developer console
          </p>
          <p style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '0.75rem' }}>
            Paste your tunnel public URL below to generate the exact webhook paths:
          </p>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <label style={{ fontSize: '0.75rem', color: '#64748b', whiteSpace: 'nowrap' }}>Public base URL</label>
            <input
              type="url"
              placeholder="https://abc123.ngrok-free.app"
              value={baseUrl}
              onChange={e => setBaseUrl(e.target.value)}
              style={{ ...inputStyle, flex: 1 }}
            />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
            {WEBHOOK_PATHS.map(({ id, label, path }) => (
              <div key={id} style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
                <span style={{ width: '6.5rem', fontSize: '0.75rem', color: '#94a3b8', flexShrink: 0 }}>{label}</span>
                <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: '0.5rem', background: '#0f172a', border: '1px solid #1e293b', borderRadius: '5px', padding: '0.3rem 0.625rem' }}>
                  <code style={{ flex: 1, fontSize: '0.75rem', color: '#a3e635', fontFamily: 'monospace', overflowX: 'auto', whiteSpace: 'nowrap' }}>
                    {displayUrl}{path}
                  </code>
                  <CopyButton text={displayUrl !== '<public-url>' ? `${displayUrl}${path}` : `${path}`} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

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

  const showWebhookSecret = ['whatsapp', 'whatsapp_linked', 'messenger', 'twitter'].includes(channel.id);
  const showVerifyToken = ['whatsapp', 'messenger'].includes(channel.id);
  const showBotToken = channel.id === 'telegram';
  const showAccountSID = ['twilio_sms', 'twilio_voice'].includes(channel.id);
  const showBearerToken = ['twitter', 'twilio_sms', 'twilio_voice', 'whatsapp_linked'].includes(channel.id);

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

// ─── Linked Devices Panel ─────────────────────────────────────────────────────

const PLATFORM_ICONS: Record<string, string> = {
  iOS: '🍎',
  Android: '🤖',
  Web: '🌐',
  Desktop: '🖥️',
};

function LinkedDevicesPanel() {
  const [data, setData] = useState<LinkedDevicesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchDevices = useCallback(() => {
    setLoading(true);
    api.commsLinkedDevices()
      .then(setData)
      .catch((err: unknown) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchDevices(); }, [fetchDevices]);
  useInterval(fetchDevices, 30000);

  const devices: LinkedDevice[] = data?.devices ?? [];
  const suspiciousCount = data?.suspicious_count ?? 0;

  return (
    <div className="card" style={{ borderLeft: `3px solid ${suspiciousCount > 0 ? '#dc2626' : '#22c55e'}` }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <span style={{ fontSize: '1.25rem' }}>📲</span>
          <div>
            <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.9375rem' }}>
              WhatsApp Linked Devices
            </div>
            {data && (
              <div style={{ fontSize: '0.75rem', color: '#64748b' }}>
                Account <code style={{ color: '#94a3b8' }}>{data.account_id}</code>
                {' · '}
                {data.total} device{data.total !== 1 ? 's' : ''}
              </div>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {suspiciousCount > 0 && (
            <span style={{
              fontSize: '0.7rem', fontWeight: 700, padding: '0.2rem 0.6rem',
              borderRadius: '9999px', background: '#450a0a', color: '#fca5a5',
              border: '1px solid #7f1d1d',
            }}>
              ⚠️ {suspiciousCount} SUSPICIOUS
            </span>
          )}
          <button className="btn-secondary" onClick={fetchDevices} style={{ fontSize: '0.75rem', padding: '0.25rem 0.6rem' }}>↻</button>
        </div>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      {loading ? (
        <div className="loading">Loading linked devices…</div>
      ) : devices.length === 0 ? (
        <div className="empty-state">No linked devices found. Configure the WhatsApp Linked Devices channel to start monitoring.</div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '0.75rem' }}>
          {devices.map((dev) => (
            <div
              key={dev.device_id}
              style={{
                background: '#0f172a',
                border: `1px solid ${dev.suspicious ? '#7f1d1d' : dev.status === 'active' ? '#1e3a5f' : '#1e293b'}`,
                borderLeft: `3px solid ${dev.suspicious ? '#dc2626' : dev.status === 'active' ? '#3b82f6' : '#334155'}`,
                borderRadius: '8px',
                padding: '0.875rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ fontSize: '1.25rem' }}>{PLATFORM_ICONS[dev.platform] ?? '📱'}</span>
                  <div>
                    <div style={{ fontSize: '0.875rem', fontWeight: 600, color: '#f1f5f9' }}>{dev.name}</div>
                    <div style={{ fontSize: '0.7rem', color: '#64748b' }}>{dev.platform}</div>
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '0.25rem' }}>
                  <span style={{
                    fontSize: '0.6rem', fontWeight: 700, padding: '0.1rem 0.45rem',
                    borderRadius: '9999px',
                    background: dev.status === 'active' ? '#052e16' : '#1e293b',
                    color: dev.status === 'active' ? '#4ade80' : '#64748b',
                    border: `1px solid ${dev.status === 'active' ? '#166534' : '#334155'}`,
                  }}>
                    {dev.status.toUpperCase()}
                  </span>
                  {dev.suspicious && (
                    <span style={{
                      fontSize: '0.6rem', fontWeight: 700, padding: '0.1rem 0.45rem',
                      borderRadius: '9999px', background: '#450a0a', color: '#fca5a5',
                      border: '1px solid #7f1d1d',
                    }}>
                      ⚠️ SUSPICIOUS
                    </span>
                  )}
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem', marginTop: '0.5rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem' }}>
                  <span style={{ color: '#64748b' }}>Device ID</span>
                  <code style={{ color: '#475569' }}>{dev.device_id}</code>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem' }}>
                  <span style={{ color: '#64748b' }}>Linked</span>
                  <span style={{ color: '#94a3b8' }}>{new Date(dev.linked_at).toLocaleDateString()}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem' }}>
                  <span style={{ color: '#64748b' }}>Last Active</span>
                  <span style={{ color: '#94a3b8' }}>{new Date(dev.last_active).toLocaleString()}</span>
                </div>
              </div>
              {dev.suspicious && (
                <div style={{ marginTop: '0.625rem', padding: '0.375rem 0.5rem', background: '#450a0a', border: '1px solid #7f1d1d', borderRadius: '6px', fontSize: '0.7rem', color: '#fca5a5' }}>
                  This device was linked recently from an unrecognised location. Review and revoke if unauthorized.
                </div>
              )}
              <button
                style={{
                  marginTop: '0.625rem', width: '100%', padding: '0.35rem',
                  background: dev.suspicious ? '#7f1d1d' : '#1e293b',
                  border: `1px solid ${dev.suspicious ? '#dc2626' : '#334155'}`,
                  borderRadius: '6px', color: dev.suspicious ? '#fca5a5' : '#64748b',
                  fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer',
                }}
                title="Revoke — remove this linked device session"
              >
                {dev.suspicious ? '🚫 Revoke Device' : 'Revoke'}
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── WhatsApp Live Session Panel ──────────────────────────────────────────────

function WhatsAppSessionPanel() {
  const [status, setStatus] = useState<WAStatus | null>(null);
  const [qrData, setQrData] = useState<WAQRData | null>(null);
  const [messages, setMessages] = useState<WAMessage[]>([]);

  const fetchStatus = useCallback(() => {
    api.waStatus().then(setStatus).catch(() => {});
  }, []);

  const fetchQR = useCallback(() => {
    api.waQR().then(setQrData).catch(() => {});
  }, []);

  const fetchMessages = useCallback(() => {
    api.waMessages().then((r) => setMessages(r.messages)).catch(() => {});
  }, []);

  useEffect(() => { fetchStatus(); }, [fetchStatus]);
  useInterval(fetchStatus, 5000);

  useEffect(() => {
    if (status?.state === 'qr_ready') fetchQR();
  }, [status?.state, fetchQR]);
  useInterval(() => { if (status?.state === 'qr_ready') fetchQR(); }, 20000);

  useEffect(() => {
    if (status?.state === 'connected') fetchMessages();
  }, [status?.state, fetchMessages]);
  useInterval(() => { if (status?.state === 'connected') fetchMessages(); }, 3000);

  const handleConnect = () => api.waConnect().then(fetchStatus).catch(() => {});
  const handleLogout = () =>
    api.waLogout().then(() => { setMessages([]); fetchStatus(); }).catch(() => {});

  const stateColor =
    ({ disconnected: '#475569', connecting: '#f59e0b', qr_ready: '#3b82f6', connected: '#22c55e' } as Record<string, string>)[
      status?.state ?? 'disconnected'
    ] ?? '#475569';

  return (
    <div className="card" style={{ marginBottom: '1.25rem', borderLeft: `3px solid ${stateColor}` }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <span style={{ fontSize: '1.25rem' }}>📱</span>
          <div>
            <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.9375rem' }}>WhatsApp Live Session</div>
            <div style={{ fontSize: '0.75rem', color: '#64748b' }}>QR-code companion device · multi-device protocol</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <span style={{
            fontSize: '0.7rem', fontWeight: 700, padding: '0.15rem 0.5rem',
            borderRadius: '9999px', background: '#1e293b', color: stateColor, border: `1px solid ${stateColor}`,
          }}>
            {(status?.state ?? 'disconnected').toUpperCase().replace('_', ' ')}
          </span>
          {status?.state !== 'connected' && status?.state !== 'qr_ready' && (
            <button
              className="btn-secondary"
              onClick={handleConnect}
              style={{ fontSize: '0.75rem', padding: '0.25rem 0.75rem' }}
            >
              Connect
            </button>
          )}
          {(status?.state === 'connected' || status?.state === 'qr_ready') && (
            <button
              className="btn-secondary"
              onClick={handleLogout}
              style={{ fontSize: '0.75rem', padding: '0.25rem 0.75rem', color: '#f87171' }}
            >
              Logout
            </button>
          )}
        </div>
      </div>

      {/* QR code */}
      {status?.state === 'qr_ready' && qrData?.qr_image && (
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          padding: '1.5rem', background: '#fff', borderRadius: '12px',
          marginBottom: '1rem', maxWidth: '320px', margin: '0 auto 1rem',
        }}>
          <img src={qrData.qr_image} alt="WhatsApp QR Code" style={{ width: 300, height: 300, display: 'block' }} />
          <div style={{ marginTop: '0.75rem', fontSize: '0.8125rem', color: '#1e293b', textAlign: 'center', fontWeight: 500 }}>
            Open WhatsApp → Linked Devices → Link a Device
            <br />
            <span style={{ fontSize: '0.7rem', color: '#64748b' }}>
              {qrData.expires_at ? `Expires ${new Date(qrData.expires_at).toLocaleTimeString()}` : 'Scan now'}
            </span>
          </div>
        </div>
      )}

      {/* Connected info */}
      {status?.state === 'connected' && (
        <div style={{
          display: 'flex', gap: '1.5rem', padding: '0.75rem',
          background: '#052e16', borderRadius: '8px', marginBottom: '1rem',
          border: '1px solid #166534', flexWrap: 'wrap',
        }}>
          <div>
            <div style={{ fontSize: '0.7rem', color: '#4ade80' }}>Phone</div>
            <div style={{ fontSize: '0.875rem', color: '#f1f5f9', fontWeight: 600 }}>+{status.phone}</div>
          </div>
          {(status.message_count ?? 0) > 0 && (
            <div>
              <div style={{ fontSize: '0.7rem', color: '#4ade80' }}>Messages</div>
              <div style={{ fontSize: '0.875rem', color: '#f1f5f9', fontWeight: 600 }}>{status.message_count}</div>
            </div>
          )}
          {status.connected_since && (
            <div>
              <div style={{ fontSize: '0.7rem', color: '#4ade80' }}>Since</div>
              <div style={{ fontSize: '0.875rem', color: '#f1f5f9' }}>{new Date(status.connected_since).toLocaleTimeString()}</div>
            </div>
          )}
        </div>
      )}

      {/* Intercepted messages */}
      {status?.state === 'connected' && messages.length > 0 && (
        <div>
          <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#94a3b8', marginBottom: '0.5rem' }}>
            Intercepted Messages
          </div>
          <div style={{ maxHeight: '320px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
            {messages.slice(0, 50).map((msg) => (
              <div
                key={msg.id}
                style={{
                  padding: '0.5rem 0.75rem',
                  background: msg.from_me ? '#1e3a5f' : '#0f172a',
                  borderRadius: '6px',
                  border: `1px solid ${msg.from_me ? '#1d4ed8' : '#1e293b'}`,
                  borderLeft: `3px solid ${msg.from_me ? '#3b82f6' : '#475569'}`,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                  <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontWeight: 600 }}>
                    {msg.from_me ? '📤 You' : `📩 +${msg.sender}`}
                    {msg.is_group && <span style={{ marginLeft: '0.3rem', color: '#64748b' }}>· group</span>}
                  </span>
                  <span style={{ fontSize: '0.65rem', color: '#475569' }}>
                    {new Date(msg.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div style={{ fontSize: '0.8125rem', color: '#e2e8f0' }}>
                  {msg.has_media && !msg.content && '📎 [media]'}
                  {msg.content || (msg.has_media ? '' : '[no content]')}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {status?.state === 'connected' && messages.length === 0 && (
        <div className="empty-state">
          Waiting for messages… Send or receive a WhatsApp message to see it here.
        </div>
      )}
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

  // Tab state.
  const [tab, setTab] = useState<'overview' | 'events' | 'config'>('overview');

  // Domain config state (Configuration tab).
  const [domainConfig, setDomainConfig] = useState<CommsGuardConfigResponse | null>(null);
  const [domainConfigLoading, setDomainConfigLoading] = useState(false);
  const [domainConfigError, setDomainConfigError] = useState<string | null>(null);
  const [globalForm, setGlobalForm] = useState<CommsGlobalConfig>({ content_analysis: true, bulk_threshold: 10, bulk_window_sec: 60 });
  const [globalEditing, setGlobalEditing] = useState(false);
  const [savingGlobal, setSavingGlobal] = useState(false);
  const [channelEditId, setChannelEditId] = useState<string | null>(null);
  const [channelEditForm, setChannelEditForm] = useState<CommsChannelConfigPatch>({ enabled: false });
  const [savingChannel, setSavingChannel] = useState(false);

  const { addToast } = useToast();

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

  const loadDomainConfig = useCallback(async () => {
    setDomainConfigLoading(true);
    setDomainConfigError(null);
    try {
      const cfg = await api.configCommsGuard();
      setDomainConfig(cfg);
      setGlobalForm({ content_analysis: cfg.content_analysis, bulk_threshold: cfg.bulk_threshold, bulk_window_sec: cfg.bulk_window_sec });
    } catch (e) {
      setDomainConfigError(e instanceof Error ? e.message : 'Failed to load CommsGuard config');
    } finally {
      setDomainConfigLoading(false);
    }
  }, []);

  async function saveGlobal() {
    setSavingGlobal(true);
    try {
      await api.updateCommsGuardGlobal(globalForm);
      setDomainConfig(prev => prev ? {
        ...prev,
        content_analysis: globalForm.content_analysis ?? prev.content_analysis,
        bulk_threshold: globalForm.bulk_threshold ?? prev.bulk_threshold,
        bulk_window_sec: globalForm.bulk_window_sec ?? prev.bulk_window_sec,
      } : prev);
      setGlobalEditing(false);
      addToast('Global settings saved', 'success');
    } catch (e) {
      addToast(e instanceof Error ? e.message : 'Failed to save global settings', 'error');
    } finally {
      setSavingGlobal(false);
    }
  }

  function openChannelEdit(id: string, entry: CommsChannelConfigEntry | undefined) {
    setChannelEditId(id);
    setChannelEditForm({ enabled: entry?.enabled ?? false, webhook_url: entry?.webhook_url });
  }

  async function saveChannel(id: string) {
    setSavingChannel(true);
    try {
      await api.updateCommsGuardChannel(id, channelEditForm);
      setDomainConfig(prev => {
        if (!prev) return prev;
        return { ...prev, channels: { ...prev.channels, [id]: { ...(prev.channels[id] ?? {}), ...channelEditForm } } };
      });
      setChannelEditId(null);
      const ch = CHANNELS_LIST.find(c => c.id === id);
      addToast(`${ch?.name ?? id} configuration saved`, 'success');
    } catch (e) {
      addToast(e instanceof Error ? e.message : 'Failed to save channel config', 'error');
    } finally {
      setSavingChannel(false);
    }
  }

  useEffect(() => { fetchStats(); fetchConfig(); }, [fetchStats, fetchConfig]);
  useInterval(fetchStats, 20000);
  useEffect(() => { if (tab === 'config') void loadDomainConfig(); }, [tab, loadDomainConfig]);

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
        <button className="btn-secondary" onClick={() => { fetchStats(); fetchConfig(); if (tab === 'config') void loadDomainConfig(); }}>
          ↻ Refresh
        </button>
      </div>

      {error && <div className="error-msg">⚠️ {error}</div>}

      {/* ─── Tabs ─────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: '0.25rem', marginBottom: '1.5rem', borderBottom: '1px solid #334155' }}>
        {(['overview', 'events', 'config'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: '0.625rem 1.25rem',
              background: 'none',
              border: 'none',
              borderBottom: `2px solid ${tab === t ? '#3b82f6' : 'transparent'}`,
              color: tab === t ? '#60a5fa' : '#64748b',
              fontWeight: 600,
              fontSize: '0.875rem',
              cursor: 'pointer',
              transition: 'color 0.12s, border-color 0.12s',
              marginBottom: '-1px',
            }}
          >
            {t === 'overview' ? 'Overview' : t === 'events' ? 'Events' : '⚙️ Configuration'}
          </button>
        ))}
      </div>

      {/* ─── Overview tab ─────────────────────────────────────────────────── */}
      {tab === 'overview' && (
        <div>
          {/* Statistics Row */}
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

          {/* Channel Cards Grid */}
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

          {/* WhatsApp Linked Devices */}
          {channels.some((c) => c.id === 'whatsapp_linked') && (
            <div style={{ marginBottom: '1.5rem' }}>
              <LinkedDevicesPanel />
            </div>
          )}

          {/* WhatsApp Live Session (QR-based) */}
          <div style={{ marginBottom: '1.5rem' }}>
            <WhatsAppSessionPanel />
          </div>

          {/* Threat Distribution + Global Config */}
          <div className="card-grid">
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

            {!configLoading && config && (
              <div className="card">
                <div className="section-title">Global Settings</div>
                <table>
                  <tbody>
                    <tr>
                      <td style={{ color: '#64748b', fontSize: '0.8125rem' }}>Content Analysis</td>
                      <td>
                        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: config.enable_content_analysis ? '#86efac' : '#f87171' }}>
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
        </div>
      )}

      {/* ─── Events tab ───────────────────────────────────────────────────── */}
      {tab === 'events' && (
        <CommsEventsTable
          channelFilter={channelFilter}
          onChannelChange={setChannelFilter}
        />
      )}

      {/* ─── Config tab ───────────────────────────────────────────────────── */}
      {tab === 'config' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {domainConfigLoading && (
            <>
              <div className="loading-skeleton" style={{ height: '8rem', borderRadius: '8px' }} />
              <div className="loading-skeleton" style={{ height: '20rem', borderRadius: '8px' }} />
            </>
          )}
          {domainConfigError && (
            <div className="error-msg" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span>⚠️ {domainConfigError}</span>
              <button onClick={() => void loadDomainConfig()} style={{ background: 'none', border: 'none', color: '#f87171', cursor: 'pointer', textDecoration: 'underline', fontWeight: 600 }}>Retry</button>
            </div>
          )}
          {!domainConfigLoading && !domainConfigError && domainConfig && (
            <>
              {/* Global Settings */}
              <div className="card">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                  <div className="section-title">🌐 Global Settings</div>
                  {!globalEditing ? (
                    <button className="btn-secondary" onClick={() => setGlobalEditing(true)}>Edit</button>
                  ) : (
                    <div style={{ display: 'flex', gap: '0.5rem' }}>
                      <button className="btn-secondary" onClick={() => { setGlobalEditing(false); setGlobalForm({ content_analysis: domainConfig.content_analysis, bulk_threshold: domainConfig.bulk_threshold, bulk_window_sec: domainConfig.bulk_window_sec }); }}>Cancel</button>
                      <button onClick={() => void saveGlobal()} disabled={savingGlobal} style={{ padding: '0.375rem 1rem', background: '#1d4ed8', border: '1px solid #2563eb', borderRadius: '6px', color: '#fff', fontWeight: 600, cursor: savingGlobal ? 'not-allowed' : 'pointer', opacity: savingGlobal ? 0.7 : 1, fontSize: '0.875rem' }}>
                        {savingGlobal ? 'Saving…' : 'Save'}
                      </button>
                    </div>
                  )}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '1.25rem' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Content Analysis</label>
                    {globalEditing ? (
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <button onClick={() => setGlobalForm(f => ({ ...f, content_analysis: true }))} style={{ flex: 1, padding: '0.5rem', borderRadius: '6px', border: globalForm.content_analysis ? '2px solid #22c55e' : '1px solid #334155', background: globalForm.content_analysis ? '#14532d' : '#0f172a', color: globalForm.content_analysis ? '#4ade80' : '#64748b', fontWeight: 600, cursor: 'pointer', fontSize: '0.875rem' }}>Enabled</button>
                        <button onClick={() => setGlobalForm(f => ({ ...f, content_analysis: false }))} style={{ flex: 1, padding: '0.5rem', borderRadius: '6px', border: !globalForm.content_analysis ? '2px solid #475569' : '1px solid #334155', background: !globalForm.content_analysis ? '#1e293b' : '#0f172a', color: !globalForm.content_analysis ? '#94a3b8' : '#64748b', fontWeight: 600, cursor: 'pointer', fontSize: '0.875rem' }}>Disabled</button>
                      </div>
                    ) : (
                      <div style={{ fontSize: '1.25rem', fontWeight: 700, color: domainConfig.content_analysis ? '#4ade80' : '#f87171' }}>
                        {domainConfig.content_analysis ? '● Enabled' : '○ Disabled'}
                      </div>
                    )}
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Bulk Message Threshold</label>
                    {globalEditing ? (
                      <input type="number" min={1} max={1000} value={globalForm.bulk_threshold ?? 10}
                        onChange={e => setGlobalForm(f => ({ ...f, bulk_threshold: Number(e.target.value) }))}
                        style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.5rem 0.75rem', color: '#f1f5f9', fontSize: '0.9375rem' }}
                      />
                    ) : (
                      <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#60a5fa' }}>{domainConfig.bulk_threshold} msgs</div>
                    )}
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em' }}>Bulk Window (seconds)</label>
                    {globalEditing ? (
                      <input type="number" min={1} max={86400} value={globalForm.bulk_window_sec ?? 60}
                        onChange={e => setGlobalForm(f => ({ ...f, bulk_window_sec: Number(e.target.value) }))}
                        style={{ width: '100%', background: '#0f172a', border: '1px solid #334155', borderRadius: '6px', padding: '0.5rem 0.75rem', color: '#f1f5f9', fontSize: '0.9375rem' }}
                      />
                    ) : (
                      <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#a78bfa' }}>{domainConfig.bulk_window_sec}s</div>
                    )}
                  </div>
                </div>
              </div>

              {/* Per-channel Configuration */}
              <div className="card">
                <div className="section-title" style={{ marginBottom: '1rem' }}>📡 Channel Configuration</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {CHANNELS_LIST.map(ch => {
                    const entry = domainConfig.channels[ch.id];
                    const isEditing = channelEditId === ch.id;
                    return (
                      <div key={ch.id} style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: '8px', padding: '1rem', borderLeft: `3px solid ${entry?.enabled ? '#16a34a' : '#334155'}` }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: isEditing ? '1rem' : 0 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
                            <span style={{ fontSize: '1.125rem' }}>{ch.icon}</span>
                            <span style={{ fontWeight: 600, color: '#f1f5f9', fontSize: '0.9375rem' }}>{ch.name}</span>
                            <span style={{ fontSize: '0.65rem', fontWeight: 700, padding: '0.1rem 0.45rem', borderRadius: '9999px', background: entry?.enabled ? '#14532d' : '#1e293b', color: entry?.enabled ? '#86efac' : '#475569', border: `1px solid ${entry?.enabled ? '#166534' : '#334155'}` }}>
                              {entry?.enabled ? 'ENABLED' : 'DISABLED'}
                            </span>
                          </div>
                          <div style={{ display: 'flex', gap: '0.5rem' }}>
                            {isEditing ? (
                              <>
                                <button className="btn-secondary" onClick={() => setChannelEditId(null)} style={{ fontSize: '0.75rem', padding: '0.25rem 0.625rem' }}>Cancel</button>
                                <button onClick={() => void saveChannel(ch.id)} disabled={savingChannel} style={{ fontSize: '0.75rem', padding: '0.25rem 0.75rem', background: '#1d4ed8', border: '1px solid #2563eb', borderRadius: '6px', color: '#fff', fontWeight: 600, cursor: savingChannel ? 'not-allowed' : 'pointer', opacity: savingChannel ? 0.7 : 1 }}>
                                  {savingChannel ? 'Saving…' : 'Save'}
                                </button>
                              </>
                            ) : (
                              <button className="btn-secondary" onClick={() => openChannelEdit(ch.id, entry)} style={{ fontSize: '0.75rem', padding: '0.25rem 0.625rem' }}>Edit</button>
                            )}
                          </div>
                        </div>
                        {isEditing && (
                          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.875rem' }}>
                            <div>
                              <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Status</label>
                              <div style={{ display: 'flex', gap: '0.5rem' }}>
                                <button onClick={() => setChannelEditForm(f => ({ ...f, enabled: true }))} style={{ flex: 1, padding: '0.375rem', borderRadius: '6px', border: channelEditForm.enabled ? '2px solid #22c55e' : '1px solid #334155', background: channelEditForm.enabled ? '#14532d' : '#0f172a', color: channelEditForm.enabled ? '#4ade80' : '#64748b', fontWeight: 600, cursor: 'pointer', fontSize: '0.8rem' }}>Enabled</button>
                                <button onClick={() => setChannelEditForm(f => ({ ...f, enabled: false }))} style={{ flex: 1, padding: '0.375rem', borderRadius: '6px', border: !channelEditForm.enabled ? '2px solid #475569' : '1px solid #334155', background: !channelEditForm.enabled ? '#1e293b' : '#0f172a', color: !channelEditForm.enabled ? '#94a3b8' : '#64748b', fontWeight: 600, cursor: 'pointer', fontSize: '0.8rem' }}>Disabled</button>
                              </div>
                            </div>
                            {ch.fields.includes('webhook_secret') && (
                              <div>
                                <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Webhook Secret</label>
                                <input type="password" placeholder="Enter new secret…" value={channelEditForm.webhook_secret ?? ''} onChange={e => setChannelEditForm(f => ({ ...f, webhook_secret: e.target.value || undefined }))} style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '0.4rem 0.6rem', color: '#f1f5f9', fontSize: '0.875rem', boxSizing: 'border-box' }} />
                              </div>
                            )}
                            {ch.fields.includes('verify_token') && (
                              <div>
                                <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Verify Token</label>
                                <input type="password" placeholder="Enter verify token…" value={channelEditForm.verify_token ?? ''} onChange={e => setChannelEditForm(f => ({ ...f, verify_token: e.target.value || undefined }))} style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '0.4rem 0.6rem', color: '#f1f5f9', fontSize: '0.875rem', boxSizing: 'border-box' }} />
                              </div>
                            )}
                            {ch.fields.includes('bot_token') && (
                              <div>
                                <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Bot Token</label>
                                <input type="password" placeholder="Enter bot token…" value={channelEditForm.bot_token ?? ''} onChange={e => setChannelEditForm(f => ({ ...f, bot_token: e.target.value || undefined }))} style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '0.4rem 0.6rem', color: '#f1f5f9', fontSize: '0.875rem', boxSizing: 'border-box' }} />
                              </div>
                            )}
                            {ch.fields.includes('account_sid') && (
                              <div>
                                <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Account SID</label>
                                <input type="text" placeholder="AC…" value={channelEditForm.account_sid ?? ''} onChange={e => setChannelEditForm(f => ({ ...f, account_sid: e.target.value || undefined }))} style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '0.4rem 0.6rem', color: '#f1f5f9', fontSize: '0.875rem', boxSizing: 'border-box' }} />
                              </div>
                            )}
                            {ch.fields.includes('bearer_token') && (
                              <div>
                                <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Auth / Bearer Token</label>
                                <input type="password" placeholder="Enter token…" value={channelEditForm.bearer_token ?? ''} onChange={e => setChannelEditForm(f => ({ ...f, bearer_token: e.target.value || undefined }))} style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '0.4rem 0.6rem', color: '#f1f5f9', fontSize: '0.875rem', boxSizing: 'border-box' }} />
                              </div>
                            )}
                            {ch.fields.includes('webhook_url') && (
                              <div style={{ gridColumn: 'span 2' }}>
                                <label style={{ display: 'block', fontSize: '0.7rem', color: '#94a3b8', marginBottom: '0.375rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>Webhook URL</label>
                                <input type="url" placeholder="https://openguard.example.com" value={channelEditForm.webhook_url ?? ''} onChange={e => setChannelEditForm(f => ({ ...f, webhook_url: e.target.value || undefined }))} style={{ width: '100%', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '0.4rem 0.6rem', color: '#f1f5f9', fontSize: '0.875rem', boxSizing: 'border-box' }} />
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}

          {/* Tunnel Setup — always visible in config tab */}
          <TunnelSetupCard />
        </div>
      )}

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

