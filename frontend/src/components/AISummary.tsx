import type { SummaryResponse } from '../api';

interface AISummaryProps {
  data: SummaryResponse | null;
  loading: boolean;
  error: string;
  onRefresh: () => void;
}

const PROVIDER_LABELS: Record<string, string> = {
  'openai-codex':     'GPT-4o',
  'anthropic-claude': 'Claude',
  'google-gemini':    'Gemini',
};

export default function AISummary({ data, loading, error, onRefresh }: AISummaryProps) {
  const providerLabel = data ? (PROVIDER_LABELS[data.provider] ?? data.provider) : '—';

  return (
    <div className="card" style={{ marginBottom: '1.5rem', position: 'relative' }}>
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '1rem' }}>🤖</span>
          <span style={{ fontWeight: 600, color: '#f1f5f9', fontSize: '0.9375rem' }}>
            AI Security Summary
          </span>
          {data && (
            <span style={{
              fontSize: '0.7rem', fontWeight: 600, color: '#7c3aed',
              border: '1px solid #7c3aed', borderRadius: '4px', padding: '1px 6px',
            }}>
              {providerLabel}
            </span>
          )}
          {data?.cache_hit && (
            <span style={{
              fontSize: '0.7rem', color: '#64748b',
              border: '1px solid #334155', borderRadius: '4px', padding: '1px 6px',
            }}>
              cached
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {data?.generated_at && (
            <span style={{ fontSize: '0.7rem', color: '#475569' }}>
              {new Date(data.generated_at).toLocaleTimeString()}
            </span>
          )}
          <button
            className="btn-secondary"
            style={{ fontSize: '0.75rem', padding: '0.25rem 0.625rem' }}
            onClick={onRefresh}
            disabled={loading}
          >
            {loading ? '…' : '↻ Regenerate'}
          </button>
        </div>
      </div>

      {/* Body */}
      {loading && !data && (
        <div style={{ display: 'flex', gap: '0.5rem', flexDirection: 'column' }}>
          <div className="loading-skeleton" style={{ height: '0.875rem', width: '100%' }} />
          <div className="loading-skeleton" style={{ height: '0.875rem', width: '85%' }} />
          <div className="loading-skeleton" style={{ height: '0.875rem', width: '70%' }} />
        </div>
      )}

      {error && !loading && (
        <div style={{ color: '#94a3b8', fontSize: '0.875rem', fontStyle: 'italic' }}>
          {error}
        </div>
      )}

      {data && (
        <p style={{
          color: '#cbd5e1',
          fontSize: '0.9rem',
          lineHeight: 1.7,
          margin: 0,
          whiteSpace: 'pre-wrap',
        }}>
          {data.summary}
        </p>
      )}

      {/* Pulsing overlay when regenerating with stale data */}
      {loading && data && (
        <div style={{
          position: 'absolute', inset: 0, borderRadius: '8px',
          background: 'rgba(15,23,42,0.45)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: '0.8125rem', color: '#94a3b8',
        }}>
          Generating…
        </div>
      )}
    </div>
  );
}
