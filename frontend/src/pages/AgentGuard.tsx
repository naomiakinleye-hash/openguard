import { useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import type { AgentRecord, AgentStatsResponse, AgentRule } from '../api';

// ─── Severity badge ───────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
    info: 'bg-gray-100 text-gray-700 border-gray-200',
  };
  const cls = map[severity] ?? map.info;
  return (
    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-semibold uppercase tracking-wide ${cls}`}>
      {severity}
    </span>
  );
}

// ─── Agent status badge ───────────────────────────────────────────────────────

function StatusBadge({ agent }: { agent: AgentRecord }) {
  if (agent.quarantined)
    return <span className="inline-block px-2 py-0.5 rounded border text-xs font-semibold uppercase bg-red-100 text-red-800 border-red-200">Quarantined</span>;
  if (agent.suspended)
    return <span className="inline-block px-2 py-0.5 rounded border text-xs font-semibold uppercase bg-yellow-100 text-yellow-800 border-yellow-200">Suspended</span>;
  return <span className="inline-block px-2 py-0.5 rounded border text-xs font-semibold uppercase bg-green-100 text-green-800 border-green-200">Active</span>;
}

// ─── Stat card ────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, accent }: { label: string; value: number | string; sub?: string; accent?: string }) {
  const border = accent ?? 'border-l-blue-400';
  return (
    <div className={`bg-white rounded-lg shadow-sm border border-gray-200 border-l-4 ${border} p-5`}>
      <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">{label}</p>
      <p className="text-3xl font-bold text-gray-900 mt-1">{value}</p>
      {sub && <p className="text-xs text-gray-400 mt-1">{sub}</p>}
    </div>
  );
}

// ─── Agent detail modal ───────────────────────────────────────────────────────

function AgentDetailModal({ agent, onClose, onAction }: {
  agent: AgentRecord;
  onClose: () => void;
  onAction: (id: string, action: 'suspend' | 'unsuspend' | 'quarantine') => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const act = async (action: 'suspend' | 'unsuspend' | 'quarantine') => {
    setBusy(true);
    await onAction(agent.agent_id, action);
    setBusy(false);
    onClose();
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-xl shadow-2xl w-full max-w-lg p-6">
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold text-gray-900">{agent.agent_name}</h2>
            <p className="text-xs text-gray-500 font-mono">{agent.agent_id}</p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-lg leading-none">&times;</button>
        </div>

        <div className="grid grid-cols-2 gap-3 mb-5">
          <InfoRow label="Type" value={agent.agent_type} />
          <InfoRow label="Status" value={<StatusBadge agent={agent} />} />
          <InfoRow label="Token Quota" value={agent.token_quota === 0 ? 'Unlimited' : agent.token_quota.toLocaleString()} />
          <InfoRow label="Call Quota" value={agent.call_quota === 0 ? 'Unlimited' : agent.call_quota.toLocaleString()} />
          <InfoRow label="Actions" value={agent.action_count.toLocaleString()} />
          <InfoRow label="Threats" value={String(agent.threat_count)} />
          <div className="col-span-2">
            <InfoRow label="Approved Tools" value={agent.approved_tools.join(', ') || '—'} />
          </div>
          <div className="col-span-2">
            <InfoRow label="Approved Domains" value={agent.approved_domains.join(', ') || '—'} />
          </div>
          {agent.registered_at && (
            <InfoRow label="Registered" value={new Date(agent.registered_at).toLocaleString()} />
          )}
          {agent.last_activity_at && (
            <InfoRow label="Last Activity" value={new Date(agent.last_activity_at).toLocaleString()} />
          )}
        </div>

        <div className="flex gap-2 pt-4 border-t border-gray-100">
          {!agent.suspended && !agent.quarantined && (
            <button
              disabled={busy}
              onClick={() => act('suspend')}
              className="flex-1 py-2 rounded-lg bg-yellow-50 text-yellow-800 border border-yellow-200 text-sm font-semibold hover:bg-yellow-100 disabled:opacity-50"
            >
              Suspend
            </button>
          )}
          {agent.suspended && !agent.quarantined && (
            <button
              disabled={busy}
              onClick={() => act('unsuspend')}
              className="flex-1 py-2 rounded-lg bg-green-50 text-green-800 border border-green-200 text-sm font-semibold hover:bg-green-100 disabled:opacity-50"
            >
              Unsuspend
            </button>
          )}
          {!agent.quarantined && (
            <button
              disabled={busy}
              onClick={() => act('quarantine')}
              className="flex-1 py-2 rounded-lg bg-red-50 text-red-800 border border-red-200 text-sm font-semibold hover:bg-red-100 disabled:opacity-50"
            >
              Quarantine
            </button>
          )}
          <button
            onClick={onClose}
            className="flex-1 py-2 rounded-lg bg-gray-50 text-gray-700 border border-gray-200 text-sm font-semibold hover:bg-gray-100"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs text-gray-400 uppercase tracking-wide mb-0.5">{label}</p>
      <div className="text-sm text-gray-800 font-medium">{value}</div>
    </div>
  );
}

// ─── Bar chart ────────────────────────────────────────────────────────────────

function BarChart({ items }: { items: { type: string; count: number }[] }) {
  const max = Math.max(...items.map(i => i.count), 1);
  const palette = [
    'bg-red-500',
    'bg-orange-500',
    'bg-yellow-500',
    'bg-purple-500',
    'bg-blue-500',
    'bg-pink-500',
    'bg-teal-500',
  ];
  return (
    <div className="space-y-2">
      {items.map((item, idx) => (
        <div key={item.type} className="flex items-center gap-3">
          <span className="w-44 text-xs text-gray-600 truncate capitalize">{item.type.replace(/_/g, ' ')}</span>
          <div className="flex-1 h-4 bg-gray-100 rounded overflow-hidden">
            <div
              className={`h-full rounded ${palette[idx % palette.length]}`}
              style={{ width: `${(item.count / max) * 100}%` }}
            />
          </div>
          <span className="w-8 text-xs text-gray-500 text-right">{item.count}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function AgentGuard() {
  const [stats, setStats] = useState<AgentStatsResponse | null>(null);
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [rules, setRules] = useState<AgentRule[]>([]);
  const [selectedAgent, setSelectedAgent] = useState<AgentRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<'agents' | 'events' | 'rules'>('agents');
  const [events, setEvents] = useState<Record<string, unknown>[]>([]);
  const [eventsTotal, setEventsTotal] = useState(0);
  const [agentFilter, setAgentFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [eventsPage, setEventsPage] = useState(1);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [s, al, rl] = await Promise.all([
        api.agentStats(),
        api.agentList(),
        api.agentRules(),
      ]);
      setStats(s);
      setAgents(al.agents ?? []);
      setRules(rl.rules ?? []);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const loadEvents = useCallback(async () => {
    try {
      const res = await api.agentEvents(agentFilter || undefined, typeFilter || undefined, eventsPage);
      setEvents(res.events ?? []);
      setEventsTotal(res.total ?? 0);
    } catch {
      setEvents([]);
    }
  }, [agentFilter, typeFilter, eventsPage]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (tab === 'events') loadEvents(); }, [tab, loadEvents]);

  const handleAction = async (id: string, action: 'suspend' | 'unsuspend' | 'quarantine') => {
    if (action === 'suspend') await api.suspendAgent(id);
    else if (action === 'unsuspend') await api.unsuspendAgent(id);
    else await api.quarantineAgent(id);
    await load();
  };

  const activeAgents = agents.filter(a => !a.suspended && !a.quarantined);
  const suspendedAgents = agents.filter(a => a.suspended);
  const quarantinedAgents = agents.filter(a => a.quarantined);

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">AgentGuard</h1>
          <p className="text-sm text-gray-500 mt-0.5">AI agent policy enforcement and threat detection</p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-semibold hover:bg-blue-700 disabled:opacity-50"
        >
          {loading ? 'Loading…' : 'Refresh'}
        </button>
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-sm text-red-800">{error}</div>
      )}

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard label="Total Agents" value={stats?.total_agents ?? agents.length} accent="border-l-blue-400" />
        <StatCard label="Active" value={stats?.active_agents ?? activeAgents.length} accent="border-l-green-400" />
        <StatCard label="Suspended" value={stats?.suspended_count ?? suspendedAgents.length} accent="border-l-yellow-400" />
        <StatCard label="Quarantined" value={stats?.quarantine_count ?? quarantinedAgents.length} accent="border-l-red-400" />
        <StatCard label="Total Threats" value={stats?.total_threats ?? 0} accent="border-l-orange-500" />
        <StatCard label="Total Actions" value={stats?.total_actions?.toLocaleString() ?? '0'} accent="border-l-purple-400" />
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="-mb-px flex gap-6">
          {(['agents', 'events', 'rules'] as const).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`pb-3 text-sm font-semibold capitalize border-b-2 transition-colors ${
                tab === t
                  ? 'border-blue-600 text-blue-600'
                  : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >
              {t === 'agents' ? 'Agent Registry' : t === 'events' ? 'Threat Events' : 'Detection Rules'}
            </button>
          ))}
        </nav>
      </div>

      {/* ── Tab: Agent Registry ── */}
      {tab === 'agents' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Agent table */}
            <div className="lg:col-span-2 bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
              <div className="px-5 py-4 border-b border-gray-100">
                <h2 className="text-base font-semibold text-gray-900">Registered Agents</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-50 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                      <th className="px-4 py-3 text-left">Agent</th>
                      <th className="px-4 py-3 text-left">Type</th>
                      <th className="px-4 py-3 text-left">Status</th>
                      <th className="px-4 py-3 text-right">Actions</th>
                      <th className="px-4 py-3 text-right">Threats</th>
                      <th className="px-4 py-3 text-right"></th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {agents.length === 0 && (
                      <tr>
                        <td colSpan={6} className="px-4 py-8 text-center text-gray-400 text-sm">No agents registered</td>
                      </tr>
                    )}
                    {agents.map(agent => (
                      <tr key={agent.agent_id} className="hover:bg-gray-50">
                        <td className="px-4 py-3">
                          <div className="font-medium text-gray-900">{agent.agent_name}</div>
                          <div className="text-xs text-gray-400 font-mono">{agent.agent_id}</div>
                        </td>
                        <td className="px-4 py-3">
                          <span className="inline-block px-2 py-0.5 bg-gray-100 text-gray-700 rounded text-xs">
                            {agent.agent_type}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <StatusBadge agent={agent} />
                        </td>
                        <td className="px-4 py-3 text-right text-gray-600">{agent.action_count.toLocaleString()}</td>
                        <td className="px-4 py-3 text-right">
                          <span className={agent.threat_count > 0 ? 'text-red-600 font-semibold' : 'text-gray-400'}>
                            {agent.threat_count}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={() => setSelectedAgent(agent)}
                            className="text-blue-600 hover:text-blue-800 text-xs font-semibold"
                          >
                            Details
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Threat breakdown */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-5">
              <h2 className="text-base font-semibold text-gray-900 mb-4">Threat Breakdown</h2>
              {stats?.event_types && stats.event_types.length > 0 ? (
                <BarChart items={stats.event_types} />
              ) : (
                <p className="text-sm text-gray-400">No threat data available</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Tab: Threat Events ── */}
      {tab === 'events' && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-3">
            <input
              type="text"
              placeholder="Filter by agent ID…"
              value={agentFilter}
              onChange={e => { setAgentFilter(e.target.value); setEventsPage(1); }}
              className="border border-gray-200 rounded-lg px-3 py-2 text-sm w-56 focus:outline-none focus:ring-2 focus:ring-blue-300"
            />
            <input
              type="text"
              placeholder="Filter by event type…"
              value={typeFilter}
              onChange={e => { setTypeFilter(e.target.value); setEventsPage(1); }}
              className="border border-gray-200 rounded-lg px-3 py-2 text-sm w-56 focus:outline-none focus:ring-2 focus:ring-blue-300"
            />
            <button
              onClick={loadEvents}
              className="px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-semibold hover:bg-blue-700"
            >
              Search
            </button>
          </div>

          <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
              <h2 className="text-base font-semibold text-gray-900">Agent Threat Events</h2>
              <span className="text-sm text-gray-500">{eventsTotal} events</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-gray-50 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                    <th className="px-4 py-3 text-left">Time</th>
                    <th className="px-4 py-3 text-left">Agent</th>
                    <th className="px-4 py-3 text-left">Event Type</th>
                    <th className="px-4 py-3 text-left">Severity</th>
                    <th className="px-4 py-3 text-left">Indicators</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {events.length === 0 && (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-gray-400">No threaten events found</td>
                    </tr>
                  )}
                  {events.map((ev, i) => {
                    const meta = (ev.metadata as Record<string, unknown>) ?? {};
                    const indicators = (ev.indicators as string[]) ?? [];
                    return (
                      <tr key={(ev.event_id as string) ?? i} className="hover:bg-gray-50">
                        <td className="px-4 py-3 text-xs text-gray-400 whitespace-nowrap">
                          {ev.timestamp ? new Date(ev.timestamp as string).toLocaleString() : '—'}
                        </td>
                        <td className="px-4 py-3">
                          <div className="font-medium text-gray-800">{String(meta.agent_name ?? '—')}</div>
                          <div className="text-xs text-gray-400 font-mono">{String(meta.agent_id ?? '')}</div>
                        </td>
                        <td className="px-4 py-3 capitalize">
                          {String(meta.event_type ?? ev.event_type ?? '—').replace(/_/g, ' ')}
                        </td>
                        <td className="px-4 py-3">
                          <SeverityBadge severity={String(ev.severity ?? 'info')} />
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1">
                            {indicators.slice(0, 3).map(ind => (
                              <span key={ind} className="px-1.5 py-0.5 bg-red-50 text-red-700 border border-red-100 rounded text-xs">
                                {ind.replace(/_/g, ' ')}
                              </span>
                            ))}
                            {indicators.length > 3 && (
                              <span className="text-xs text-gray-400">+{indicators.length - 3} more</span>
                            )}
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {eventsTotal > 25 && (
              <div className="px-5 py-3 border-t border-gray-100 flex items-center justify-between text-sm text-gray-500">
                <span>Page {eventsPage}</span>
                <div className="flex gap-2">
                  <button
                    disabled={eventsPage <= 1}
                    onClick={() => { setEventsPage(p => p - 1); loadEvents(); }}
                    className="px-3 py-1 rounded border border-gray-200 hover:bg-gray-50 disabled:opacity-40"
                  >
                    Prev
                  </button>
                  <button
                    disabled={eventsPage * 25 >= eventsTotal}
                    onClick={() => { setEventsPage(p => p + 1); loadEvents(); }}
                    className="px-3 py-1 rounded border border-gray-200 hover:bg-gray-50 disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Tab: Detection Rules ── */}
      {tab === 'rules' && (
        <div className="space-y-4">
          {rules.map(rule => (
            <div key={rule.id} className="bg-white rounded-lg shadow-sm border border-gray-200 p-5">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-1">
                    <span className="font-mono text-xs text-gray-400 bg-gray-100 px-2 py-0.5 rounded">{rule.id}</span>
                    <h3 className="text-base font-semibold text-gray-900">{rule.name}</h3>
                    <SeverityBadge severity={rule.severity} />
                    <span className="text-xs text-gray-400 bg-gray-50 border border-gray-200 px-2 py-0.5 rounded">
                      Tier: {rule.tier}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 mb-3">{rule.description}</p>
                  <div className="flex flex-wrap gap-2">
                    {rule.responses.map(r => (
                      <span key={r} className="px-2 py-0.5 bg-blue-50 text-blue-700 border border-blue-100 rounded text-xs font-medium">
                        {r.replace(/_/g, ' ')}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="flex-shrink-0">
                  <span className={`inline-block px-2 py-0.5 rounded border text-xs font-semibold ${
                    rule.enabled
                      ? 'bg-green-50 text-green-700 border-green-200'
                      : 'bg-gray-100 text-gray-500 border-gray-200'
                  }`}>
                    {rule.enabled ? 'Enabled' : 'Disabled'}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Agent detail modal */}
      {selectedAgent && (
        <AgentDetailModal
          agent={selectedAgent}
          onClose={() => setSelectedAgent(null)}
          onAction={handleAction}
        />
      )}
    </div>
  );
}
