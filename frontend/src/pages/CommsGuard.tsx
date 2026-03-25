import { useCallback, useEffect, useMemo, useState } from 'react';
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
  { value: 'telegram', label: 'Telegram' },
  { value: 'messenger', label: 'Messenger' },
  { value: 'twilio_sms', label: 'Twilio SMS' },
  { value: 'twilio_voice', label: 'Twilio Voice' },
  { value: 'twitter', label: 'Twitter / X' },
];

const CHANNELS_LIST = [
  { id: 'whatsapp',        name: 'WhatsApp',               icon: '📱', fields: ['webhook_secret', 'verify_token', 'webhook_url'] },
  { id: 'telegram',        name: 'Telegram',               icon: '✈️',  fields: ['bot_token', 'webhook_url'] },
  { id: 'messenger',       name: 'Messenger',              icon: '💬', fields: ['webhook_secret', 'verify_token', 'webhook_url'] },
  { id: 'twilio_sms',      name: 'Twilio SMS',             icon: '📨', fields: ['account_sid', 'bearer_token', 'webhook_url'] },
  { id: 'twilio_voice',    name: 'Twilio Voice',           icon: '📞', fields: ['account_sid', 'bearer_token', 'webhook_url'] },
  { id: 'twitter',         name: 'Twitter / X',            icon: '🐦', fields: ['webhook_secret', 'bearer_token', 'webhook_url'] },
];

// ─── Adapter accent colours & descriptions ────────────────────────────────────

const ADAPTER_META: Record<string, { icon: string; name: string; accentColor: string; description: string }> = {
  whatsapp:     { icon: '📱', name: 'WhatsApp',     accentColor: '#25d366', description: 'End-to-end encrypted messaging' },
  telegram:     { icon: '✈️',  name: 'Telegram',     accentColor: '#2ca5e0', description: 'Bot API webhook listener' },
  messenger:    { icon: '💬', name: 'Messenger',    accentColor: '#0084ff', description: 'Facebook Messenger webhooks' },
  twilio_sms:   { icon: '📨', name: 'Twilio SMS',   accentColor: '#f22f46', description: 'SMS + MMS via Twilio' },
  twilio_voice: { icon: '📞', name: 'Twilio Voice', accentColor: '#e0a849', description: 'Voice call monitoring' },
  twitter:      { icon: '🐦', name: 'Twitter / X',  accentColor: '#1da1f2', description: 'DM + Activity-API stream' },
};

// ─── TunnelSetupCard ──────────────────────────────────────────────────────────

const WEBHOOK_PATHS: { id: string; label: string; path: string }[] = [
  { id: 'whatsapp',        label: 'WhatsApp',              path: '/whatsapp/webhook' },
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
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <div style={{ fontSize: '0.8125rem', fontWeight: 600, color: '#94a3b8' }}>
              Live Feed
            </div>
            {messages.some(m => m.is_flagged) && (
              <span style={{ fontSize: '0.7rem', fontWeight: 700, color: '#f87171', background: '#450a0a', border: '1px solid #7f1d1d', borderRadius: '9999px', padding: '0.1rem 0.5rem' }}>
                ⚠️ {messages.filter(m => m.is_flagged).length} blocked
              </span>
            )}
          </div>
          <div style={{ maxHeight: '380px', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.375rem' }}>
            {messages.slice(0, 50).map((msg) => {
              const borderColor = msg.is_flagged ? '#dc2626' : msg.from_me ? '#3b82f6' : '#475569';
              const bgColor     = msg.is_flagged ? '#1f0a0a' : msg.from_me ? '#1e3a5f' : '#0f172a';
              const borderSide  = msg.is_flagged ? '#dc2626' : msg.from_me ? '#1d4ed8' : '#1e293b';
              return (
                <div
                  key={msg.id}
                  style={{
                    padding: '0.5rem 0.75rem',
                    background: bgColor,
                    borderRadius: '6px',
                    border: `1px solid ${borderSide}`,
                    borderLeft: `3px solid ${borderColor}`,
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                      <span style={{ fontSize: '0.7rem', color: msg.is_flagged ? '#fca5a5' : '#94a3b8', fontWeight: 600 }}>
                        {msg.from_me ? '📤 You' : `📩 +${msg.sender}`}
                        {msg.is_group && <span style={{ marginLeft: '0.3rem', color: '#64748b' }}>· group</span>}
                      </span>
                      {msg.is_flagged && (
                        <span style={{
                          fontSize: '0.6rem', fontWeight: 800, padding: '0.05rem 0.4rem',
                          borderRadius: '9999px', background: '#7f1d1d', color: '#fca5a5',
                          border: '1px solid #dc2626', letterSpacing: '0.05em',
                        }}>
                          🚫 BLOCKED
                        </span>
                      )}
                    </div>
                    <span style={{ fontSize: '0.65rem', color: '#475569' }}>
                      {new Date(msg.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div style={{ fontSize: '0.8125rem', color: msg.is_flagged ? '#fca5a5' : '#e2e8f0', marginBottom: msg.is_flagged && msg.threats.length > 0 ? '0.375rem' : 0 }}>
                    {msg.has_media && !msg.content && '📎 [media]'}
                    {msg.content || (msg.has_media ? '' : '[no content]')}
                  </div>

                  {msg.is_flagged && msg.threats.length > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                      {msg.threats.map((t) => (
                        <span
                          key={t}
                          style={{
                            fontSize: '0.6rem', fontWeight: 700, padding: '0.1rem 0.4rem',
                            borderRadius: '4px', background: '#450a0a', color: '#f87171',
                            border: '1px solid #7f1d1d', textTransform: 'uppercase', letterSpacing: '0.04em',
                          }}
                        >
                          {t.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
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
// ─── AdapterStatusGrid ───────────────────────────────────────────────────────

function AdapterStatusGrid({ channels }: { channels: CommsChannel[] }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(172px, 1fr))', gap: '0.75rem' }}>
      {channels.map((ch) => {
        const meta = ADAPTER_META[ch.id] ?? { icon: '📡', name: ch.name, accentColor: '#64748b', description: '' };
        const hasThreat = (ch.threat_count ?? 0) > 0;
        const borderColor = hasThreat ? '#dc2626' : ch.configured ? meta.accentColor : '#334155';
        return (
          <div
            key={ch.id}
            style={{
              background: '#0f172a',
              border: '1px solid #1e293b',
              borderLeft: `3px solid ${borderColor}`,
              borderRadius: '8px',
              padding: '0.875rem',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '1.25rem' }}>{meta.icon}</span>
              <span
                style={{
                  fontSize: '0.6rem', fontWeight: 700, padding: '0.1rem 0.4rem', borderRadius: '9999px',
                  background: ch.configured ? '#14532d' : '#1e293b',
                  color: ch.configured ? '#86efac' : '#64748b',
                  border: `1px solid ${ch.configured ? '#166534' : '#334155'}`,
                }}
              >
                {ch.configured ? 'ON' : 'OFF'}
              </span>
            </div>
            <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: '#f1f5f9', marginBottom: '0.125rem' }}>{meta.name}</div>
            <div style={{ fontSize: '0.65rem', color: '#475569', marginBottom: '0.625rem' }}>{meta.description}</div>
            <div style={{ display: 'flex', gap: '1rem' }}>
              <div>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: '#cbd5e1' }}>{ch.message_count ?? 0}</div>
                <div style={{ fontSize: '0.6rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.04em' }}>msgs</div>
              </div>
              <div>
                <div style={{ fontSize: '1rem', fontWeight: 700, color: hasThreat ? '#f87171' : '#334155' }}>{ch.threat_count ?? 0}</div>
                <div style={{ fontSize: '0.6rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.04em' }}>threats</div>
              </div>
            </div>
            {ch.last_event && (
              <div style={{ fontSize: '0.6rem', color: '#334155', marginTop: '0.375rem' }}>
                {new Date(ch.last_event).toLocaleTimeString()}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── WALinkedStats ────────────────────────────────────────────────────────────

function WALinkedStats({
  status,
  messages,
  qrData,
  onConnect,
  onLogout,
}: {
  status: WAStatus | null;
  messages: WAMessage[];
  qrData: WAQRData | null;
  onConnect: () => void;
  onLogout: () => void;
}) {
  const stateColor =
    status?.state === 'connected'   ? '#22c55e' :
    status?.state === 'qr_ready'    ? '#3b82f6' :
    status?.state === 'connecting'  ? '#f59e0b' : '#475569';
  const stateLabel = (status?.state ?? 'disconnected').toUpperCase().replace('_', ' ');

  const fromMe    = messages.filter((m) => m.from_me).length;
  const fromOther = messages.filter((m) => !m.from_me).length;
  const groupMsgs = messages.filter((m) => m.is_group).length;
  const mediaMsgs = messages.filter((m) => m.has_media).length;

  const [uptimeTick, setUptimeTick] = useState(0);
  useEffect(() => {
    if (status?.state !== 'connected') return;
    const id = setInterval(() => setUptimeTick((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, [status?.state]);

  const connectedDuration = useMemo(() => {
    void uptimeTick;
    if (!status?.connected_since) return null;
    const secs = Math.floor((Date.now() - new Date(status.connected_since).getTime()) / 1000);
    if (secs < 60)   return `${secs}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
    return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  }, [status?.connected_since, uptimeTick]);

  const statCell = (label: string, value: number, color: string) => (
    <div style={{ background: '#0f172a', borderRadius: '6px', padding: '0.5rem 0.625rem', textAlign: 'center', border: '1px solid #1e293b' }}>
      <div style={{ fontSize: '1.125rem', fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: '0.6rem', color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.03em' }}>{label}</div>
    </div>
  );

  return (
    <div className="card" style={{ borderLeft: `3px solid ${stateColor}` }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.875rem' }}>
        <div>
          <div style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.9rem' }}>📱 WhatsApp Linked Device</div>
          <div style={{ fontSize: '0.7rem', color: '#64748b' }}>Multi-device protocol · live interception</div>
        </div>
        <div style={{ display: 'flex', gap: '0.375rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '0.6rem', fontWeight: 700, padding: '0.15rem 0.5rem', borderRadius: '9999px', background: '#1e293b', color: stateColor, border: `1px solid ${stateColor}40` }}>
            {stateLabel}
          </span>
          {status?.state !== 'connected' && status?.state !== 'qr_ready' && (
            <button className="btn-secondary" onClick={onConnect} style={{ fontSize: '0.7rem', padding: '0.2rem 0.6rem' }}>Connect</button>
          )}
          {(status?.state === 'connected' || status?.state === 'qr_ready') && (
            <button className="btn-secondary" onClick={onLogout} style={{ fontSize: '0.7rem', padding: '0.2rem 0.6rem', color: '#f87171' }}>Logout</button>
          )}
        </div>
      </div>

      {status?.state === 'qr_ready' && qrData?.qr_image && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '1rem', background: '#fff', borderRadius: '10px', marginBottom: '0.875rem' }}>
          <img src={qrData.qr_image} alt="WhatsApp QR" style={{ width: 240, height: 240 }} />
          <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: '#1e293b', fontWeight: 500, textAlign: 'center' }}>
            WhatsApp → Linked Devices → Link a Device
          </div>
          {qrData.expires_at && (
            <div style={{ fontSize: '0.7rem', color: '#475569', marginTop: '0.25rem' }}>
              Expires {new Date(qrData.expires_at).toLocaleTimeString()}
            </div>
          )}
        </div>
      )}

      {status?.state === 'connected' && (
        <>
          <div style={{ display: 'flex', gap: '0.75rem', padding: '0.625rem 0.875rem', background: '#052e16', borderRadius: '6px', marginBottom: '0.875rem', border: '1px solid #166534', flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontSize: '0.6rem', color: '#4ade80', textTransform: 'uppercase' }}>Phone</div>
              <div style={{ fontSize: '0.875rem', color: '#f1f5f9', fontWeight: 700 }}>+{status.phone}</div>
            </div>
            {status.name && (
              <div>
                <div style={{ fontSize: '0.6rem', color: '#4ade80', textTransform: 'uppercase' }}>Account</div>
                <div style={{ fontSize: '0.875rem', color: '#f1f5f9', fontWeight: 700 }}>{status.name}</div>
              </div>
            )}
            {connectedDuration && (
              <div>
                <div style={{ fontSize: '0.6rem', color: '#4ade80', textTransform: 'uppercase' }}>Uptime</div>
                <div style={{ fontSize: '0.875rem', color: '#f1f5f9' }}>{connectedDuration}</div>
              </div>
            )}
            <div>
              <div style={{ fontSize: '0.6rem', color: '#4ade80', textTransform: 'uppercase' }}>Session</div>
              <div style={{ fontSize: '0.875rem', color: '#22c55e', fontWeight: 700 }}>● Active</div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '0.5rem', marginBottom: '0.75rem' }}>
            {statCell('Total',    status.message_count ?? 0,                                '#60a5fa')}
            {statCell('Sent',     fromMe,                                                   '#3b82f6')}
            {statCell('Received', fromOther,                                                '#94a3b8')}
            {statCell('Groups',   groupMsgs,                                                '#a78bfa')}
            {statCell('Media',    mediaMsgs,                                                '#fbbf24')}
            {statCell('Text',     Math.max(0, (status.message_count ?? 0) - mediaMsgs),    '#64748b')}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0.75rem', background: '#0f172a', borderRadius: '6px', border: '1px solid #1e293b' }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#22c55e', boxShadow: '0 0 6px #22c55e' }} />
            <span style={{ fontSize: '0.75rem', color: '#4ade80', fontWeight: 600 }}>Session healthy</span>
            <span style={{ marginLeft: 'auto', fontSize: '0.65rem', color: '#475569' }}>Multi-device protocol</span>
          </div>
        </>
      )}

      {(status?.state === 'disconnected' || !status) && (
        <div style={{ textAlign: 'center', padding: '1.5rem', color: '#64748b', fontSize: '0.875rem' }}>
          Not connected — click <strong style={{ color: '#94a3b8' }}>Connect</strong> to link a WhatsApp device via QR code.
        </div>
      )}
      {status?.state === 'connecting' && (
        <div style={{ textAlign: 'center', padding: '1.25rem', color: '#f59e0b', fontSize: '0.875rem' }}>Connecting…</div>
      )}
    </div>
  );
}

// ─── InterceptFeed ────────────────────────────────────────────────────────────

interface FeedItem {
  id: string;
  channel: string;
  channelIcon: string;
  sender: string;
  content: string;
  timestamp: string;
  isFromMe: boolean;
  isGroup: boolean;
  hasMedia: boolean;
  isThreat: boolean;
  threatType?: string;
  riskScore?: number;
  tier?: number;
  indicators: string[];
}

function InterceptFeed({
  waMessages,
  commsEvents,
  channelFilter,
  onChannelChange,
}: {
  waMessages: WAMessage[];
  commsEvents: Event[];
  channelFilter: string;
  onChannelChange: (ch: string) => void;
}) {
  const [showThreatsOnly, setShowThreatsOnly] = useState(false);

  const feedItems: FeedItem[] = useMemo(() => {
    const items: FeedItem[] = [];

    if (!channelFilter || channelFilter === 'whatsapp') {
      for (const msg of waMessages) {
        items.push({
          id: `wa-${msg.id}`,
          channel: 'whatsapp',
          channelIcon: '📱',
          sender: msg.from_me ? 'You' : `+${msg.sender}`,
          content: msg.has_media && !msg.content ? '📎 [media attachment]' : (msg.content || '[no content]'),
          timestamp: msg.timestamp,
          isFromMe: msg.from_me,
          isGroup: msg.is_group,
          hasMedia: msg.has_media,
          isThreat: msg.is_flagged ?? false,
          indicators: msg.threats ?? [],
        });
      }
    }

    for (const ev of commsEvents) {
      const meta = ev.metadata as Record<string, unknown> | undefined;
      const evChannel = (() => {
        if (ev.source && typeof ev.source === 'object') {
          const src = ev.source as Record<string, unknown>;
          if (src.adapter) return String(src.adapter);
        }
        return meta?.channel ? String(meta.channel) : 'unknown';
      })();
      if (channelFilter && evChannel !== channelFilter) continue;
      if (evChannel === 'whatsapp' && (!channelFilter || channelFilter !== 'whatsapp')) continue;
      const evType = meta?.event_type ? String(meta.event_type) : (ev.type ?? 'unknown');
      const isThreat = evType !== 'message_received' && evType !== 'unknown' && evType !== '';
      const adMeta = ADAPTER_META[evChannel] ?? { icon: '📡', name: evChannel, accentColor: '#64748b', description: '' };
      items.push({
        id: String(ev.id ?? ev.event_id ?? Math.random()),
        channel: evChannel,
        channelIcon: adMeta.icon,
        sender: meta?.sender_id ? String(meta.sender_id) : '—',
        content: meta?.content
          ? String(meta.content)
          : isThreat ? `⚠️ ${evType.replace(/_/g, ' ')}` : '[message intercepted]',
        timestamp: String(ev.timestamp ?? ''),
        isFromMe: false,
        isGroup: false,
        hasMedia: false,
        isThreat,
        threatType: isThreat ? evType : undefined,
        riskScore: typeof ev.risk_score === 'number' ? ev.risk_score : undefined,
        tier: typeof ev.tier === 'number' ? ev.tier : undefined,
        indicators: Array.isArray(ev.indicators) ? (ev.indicators as string[]) : [],
      });
    }

    items.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    return items;
  }, [waMessages, commsEvents, channelFilter]);

  const displayItems = showThreatsOnly ? feedItems.filter((i) => i.isThreat) : feedItems;

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      <div style={{ padding: '0.75rem 1rem', borderBottom: '1px solid #334155', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem', flexWrap: 'wrap' }}>
        <div style={{ fontWeight: 600, color: '#f1f5f9', fontSize: '0.875rem' }}>
          📨 Live Intercept Feed
          <span style={{ marginLeft: '0.5rem', color: '#64748b', fontWeight: 400, fontSize: '0.8125rem' }}>
            {displayItems.length} {showThreatsOnly ? 'threat' : 'msg'}{displayItems.length !== 1 ? 's' : ''}
          </span>
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button
            onClick={() => setShowThreatsOnly((v) => !v)}
            style={{
              fontSize: '0.7rem', padding: '0.25rem 0.625rem', borderRadius: '6px', cursor: 'pointer', fontWeight: 600,
              border: `1px solid ${showThreatsOnly ? '#dc2626' : '#334155'}`,
              background: showThreatsOnly ? '#450a0a' : 'transparent',
              color: showThreatsOnly ? '#f87171' : '#64748b',
            }}
          >
            {showThreatsOnly ? '⚠️ Threats Only' : '☰ All'}
          </button>
          <select
            value={channelFilter}
            onChange={(e) => onChannelChange(e.target.value)}
            style={{ fontSize: '0.75rem', background: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '0.25rem 0.5rem', color: '#cbd5e1' }}
          >
            {CHANNEL_FILTER_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </select>
        </div>
      </div>

      <div style={{ maxHeight: '560px', overflowY: 'auto' }}>
        {displayItems.length === 0 ? (
          <div style={{ padding: '2.5rem', textAlign: 'center', color: '#475569', fontSize: '0.875rem' }}>
            {showThreatsOnly
              ? 'No threats detected yet across channels.'
              : 'No messages intercepted yet. Connect a channel or link a WhatsApp device.'}
          </div>
        ) : (
          displayItems.map((item) => (
            <div
              key={item.id}
              style={{
                padding: '0.625rem 1rem',
                borderBottom: '1px solid #0f172a',
                background: item.isThreat
                  ? 'rgba(127,29,29,0.15)'
                  : item.isFromMe
                  ? 'rgba(29,78,216,0.08)'
                  : 'transparent',
                borderLeft: `3px solid ${
                  item.isThreat
                    ? TIER_COLORS[item.tier ?? 3] ?? '#dc2626'
                    : item.isFromMe
                    ? '#1d4ed8'
                    : '#1e293b'
                }`,
                display: 'flex', gap: '0.625rem', alignItems: 'flex-start',
              }}
            >
              <span style={{ fontSize: '0.875rem', flexShrink: 0, marginTop: '0.1rem' }}>{item.channelIcon}</span>

              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.2rem', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontWeight: 600 }}>{item.sender}</span>
                    <span style={{ fontSize: '0.6rem', color: '#475569', background: '#1e293b', padding: '0.05rem 0.35rem', borderRadius: '9999px' }}>
                      {item.channel}
                    </span>
                    {item.isGroup && (
                      <span style={{ fontSize: '0.6rem', color: '#64748b', background: '#1e293b', padding: '0.05rem 0.35rem', borderRadius: '9999px' }}>group</span>
                    )}
                    {item.hasMedia && (
                      <span style={{ fontSize: '0.6rem', color: '#a78bfa', background: 'rgba(167,139,250,0.1)', padding: '0.05rem 0.35rem', borderRadius: '9999px', border: '1px solid rgba(167,139,250,0.2)' }}>media</span>
                    )}
                    {item.isThreat && item.threatType && (
                      <span
                        style={{
                          fontSize: '0.6rem', fontWeight: 700, padding: '0.1rem 0.4rem', borderRadius: '9999px',
                          color: EVENT_TYPE_COLORS[item.threatType] ?? '#f87171',
                          background: 'rgba(127,29,29,0.3)',
                          border: `1px solid ${(EVENT_TYPE_COLORS[item.threatType] ?? '#f87171')}40`,
                        }}
                      >
                        ⚠ {item.threatType.replace(/_/g, ' ')}
                      </span>
                    )}
                  </div>
                  <span style={{ fontSize: '0.65rem', color: '#475569', flexShrink: 0 }}>
                    {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '—'}
                  </span>
                </div>
                <div
                  style={{
                    fontSize: '0.8125rem',
                    color: item.isThreat ? '#fca5a5' : '#cbd5e1',
                    overflow: 'hidden', textOverflow: 'ellipsis',
                    display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
                  }}
                >
                  {item.content}
                </div>
                {item.isThreat && item.indicators.length > 0 && (
                  <div style={{ display: 'flex', gap: '0.25rem', marginTop: '0.3rem', flexWrap: 'wrap' }}>
                    {item.indicators.slice(0, 4).map((ind, j) => (
                      <span key={j} style={{ fontSize: '0.6rem', padding: '0.05rem 0.35rem', borderRadius: '9999px', background: '#450a0a', color: '#fca5a5', border: '1px solid #7f1d1d' }}>
                        {ind}
                      </span>
                    ))}
                    {item.indicators.length > 4 && (
                      <span style={{ fontSize: '0.6rem', color: '#64748b' }}>+{item.indicators.length - 4}</span>
                    )}
                  </div>
                )}
              </div>

              {item.riskScore !== undefined && (
                <div style={{ textAlign: 'center', flexShrink: 0, minWidth: 32 }}>
                  <div style={{ fontSize: '0.875rem', fontWeight: 700, color: item.riskScore > 70 ? '#f87171' : item.riskScore > 40 ? '#fbbf24' : '#64748b' }}>
                    {Math.round(item.riskScore)}
                  </div>
                  <div style={{ fontSize: '0.55rem', color: '#475569', textTransform: 'uppercase' }}>risk</div>
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// ─── ThreatAlertBanner ────────────────────────────────────────────────────────

function ThreatAlertBanner({ threatChannels, totalThreats }: { threatChannels: CommsChannel[]; totalThreats: number }) {
  if (totalThreats === 0) return null;
  return (
    <div
      style={{
        padding: '0.75rem 1rem', background: 'rgba(127,29,29,0.25)',
        border: '1px solid #7f1d1d', borderRadius: '8px', marginBottom: '1.25rem',
        display: 'flex', alignItems: 'center', gap: '0.875rem',
      }}
    >
      <span style={{ fontSize: '1.25rem' }}>🚨</span>
      <div style={{ flex: 1 }}>
        <div style={{ fontSize: '0.875rem', fontWeight: 700, color: '#fca5a5' }}>
          {totalThreats} active threat{totalThreats !== 1 ? 's' : ''} detected across communication channels
        </div>
        <div style={{ fontSize: '0.75rem', color: '#f87171', marginTop: '0.125rem' }}>
          Affected: {threatChannels.map((c) => c.name).join(' · ')}
        </div>
      </div>
    </div>
  );
}

// ─── InterceptionTab ──────────────────────────────────────────────────────────

function InterceptionTab({ channels, stats }: { channels: CommsChannel[]; stats: CommsStatsResponse | null }) {
  const [waStatus, setWaStatus]       = useState<WAStatus | null>(null);
  const [waQrData, setWaQrData]       = useState<WAQRData | null>(null);
  const [waMessages, setWaMessages]   = useState<WAMessage[]>([]);
  const [commsEventsData, setCommsEventsData] = useState<CommsEventsResponse | null>(null);
  const [interceptChannelFilter, setInterceptChannelFilter] = useState('');

  const fetchWaStatus    = useCallback(() => { api.waStatus().then(setWaStatus).catch(() => {}); }, []);
  const fetchWaQR        = useCallback(() => { api.waQR().then(setWaQrData).catch(() => {}); }, []);
  const fetchWaMessages  = useCallback(() => { api.waMessages().then((r) => setWaMessages(r.messages)).catch(() => {}); }, []);
  const fetchCommsEvents = useCallback(() => { api.commsEvents(undefined, 1).then(setCommsEventsData).catch(() => {}); }, []);

  useEffect(() => { fetchWaStatus(); fetchCommsEvents(); }, [fetchWaStatus, fetchCommsEvents]);
  useInterval(fetchWaStatus, 5000);

  useEffect(() => {
    if (waStatus?.state === 'qr_ready') fetchWaQR();
  }, [waStatus?.state, fetchWaQR]);
  useInterval(() => { if (waStatus?.state === 'qr_ready') fetchWaQR(); }, 20000);

  useEffect(() => {
    if (waStatus?.state === 'connected') fetchWaMessages();
  }, [waStatus?.state, fetchWaMessages]);
  useInterval(() => { if (waStatus?.state === 'connected') fetchWaMessages(); }, 3000);
  useInterval(fetchCommsEvents, 10000);

  const handleConnect = () => { void api.waConnect().then(fetchWaStatus); };
  const handleLogout  = () => { void api.waLogout().then(() => { setWaMessages([]); fetchWaStatus(); }); };

  const commsEventsList = commsEventsData?.events ?? [];
  const threatChannels  = channels.filter((ch) => (ch.threat_count ?? 0) > 0);
  const waChannel       = channels.find((c) => c.id === 'whatsapp');

  return (
    <div>
      <ThreatAlertBanner threatChannels={threatChannels} totalThreats={stats?.total_threats ?? 0} />

      {/* Adapter Status Grid */}
      <div style={{ marginBottom: '1.25rem' }}>
        <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.625rem' }}>
          Adapter Status — All Channels
        </div>
        <AdapterStatusGrid channels={channels} />
      </div>

      {/* Two-column layout */}
      <div style={{ display: 'flex', gap: '1.25rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
        {/* Left: Live message feed */}
        <div style={{ flex: '1 1 380px', minWidth: 0 }}>
          <InterceptFeed
            waMessages={waMessages}
            commsEvents={commsEventsList}
            channelFilter={interceptChannelFilter}
            onChannelChange={setInterceptChannelFilter}
          />
        </div>

        {/* Right: WA stats + summary */}
        <div style={{ width: '340px', flexShrink: 0, display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <WALinkedStats
            status={waStatus}
            messages={waMessages}
            qrData={waQrData}
            onConnect={handleConnect}
            onLogout={handleLogout}
          />

          {/* Per-adapter threat breakdown */}
          {threatChannels.length > 0 && (
            <div className="card">
              <div className="section-title" style={{ marginBottom: '0.75rem' }}>⚠️ Threat Rate by Adapter</div>
              {threatChannels
                .sort((a, b) => (b.threat_count ?? 0) - (a.threat_count ?? 0))
                .map((ch) => {
                  const meta = ADAPTER_META[ch.id] ?? { icon: '📡', name: ch.name, accentColor: '#dc2626', description: '' };
                  const maxMsg = Math.max(1, ch.message_count ?? 1);
                  const pct = Math.round(((ch.threat_count ?? 0) / maxMsg) * 100);
                  return (
                    <div key={ch.id} style={{ marginBottom: '0.75rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                        <span style={{ fontSize: '0.8125rem', color: '#cbd5e1' }}>{meta.icon} {meta.name}</span>
                        <span style={{ fontSize: '0.75rem', color: '#f87171', fontWeight: 600 }}>
                          {ch.threat_count} ({pct}%)
                        </span>
                      </div>
                      <div style={{ background: '#0f172a', borderRadius: '4px', height: '6px', overflow: 'hidden' }}>
                        <div style={{ height: '100%', borderRadius: '4px', width: `${Math.min(100, pct)}%`, background: meta.accentColor, transition: 'width 0.4s ease' }} />
                      </div>
                    </div>
                  );
                })}
            </div>
          )}

          {/* Session summary */}
          <div className="card">
            <div className="section-title" style={{ marginBottom: '0.75rem' }}>📊 Session Summary</div>
            <table style={{ width: '100%' }}>
              <tbody>
                {[
                  { label: 'Total Events',    value: stats?.total_events ?? 0,         color: '#60a5fa' },
                  { label: 'Threats Detected', value: stats?.total_threats ?? 0,        color: (stats?.total_threats ?? 0) > 0 ? '#f87171' : '#64748b' },
                  { label: 'Active Channels', value: channels.filter((c) => c.configured).length, color: '#4ade80' },
                  { label: 'WA Messages',     value: waMessages.length,                color: '#25d366' },
                  { label: 'WA Threat Events', value: waChannel?.threat_count ?? 0,    color: '#f87171' },
                ].map((row) => (
                  <tr key={row.label}>
                    <td style={{ color: '#64748b', fontSize: '0.8125rem', padding: '0.3rem 0' }}>{row.label}</td>
                    <td style={{ color: row.color, fontWeight: 700, fontSize: '0.9rem', textAlign: 'right' }}>{row.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

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
  const [tab, setTab] = useState<'overview' | 'interception' | 'events' | 'config'>('overview');

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

  // ── Interception tab tracks threat channel list ──
  // (no extra fetch needed — uses shared stats/channels state)

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
        {(['overview', 'interception', 'events', 'config'] as const).map(t => (
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
            {t === 'overview' ? 'Overview' : t === 'interception' ? '🔭 Interception' : t === 'events' ? 'Events' : '⚙️ Configuration'}
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

          {/* Adapter status mini-grid */}
          {!statsLoading && channels.length > 0 && (
            <div style={{ marginBottom: '1.25rem' }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: '0.5rem' }}>
                Adapter Status
              </div>
              <AdapterStatusGrid channels={channels} />
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

      {/* ─── Interception tab ─────────────────────────────────────────────── */}
      {tab === 'interception' && (
        <InterceptionTab channels={channels} stats={stats} />
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

