// api.ts — typed wrappers around the OpenGuard v5 console REST API.

const BASE = import.meta.env.VITE_API_BASE ?? '';

/** Read the JWT token from localStorage (set at login). */
function authHeaders(): HeadersInit {
  const token = localStorage.getItem('og_token') ?? '';
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function del<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function putJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', ...authHeaders() },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

/** Build a query string from a record, omitting undefined/empty values. */
function buildQuery(params: Record<string, string | undefined>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') {
      parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    }
  }
  return parts.length > 0 ? `?${parts.join('&')}` : '';
}

// ─── Response shapes ─────────────────────────────────────────────────────────

export interface LoginResponse {
  token: string;
}

export interface HealthResponse {
  status: string;
  version: string;
}

export interface EventsResponse {
  events: Event[];
  page: number;
  total: number;
}

export interface Event {
  id?: string;
  event_id?: string;
  type?: string;
  source?: string | Record<string, unknown>;
  tier?: number | string;
  risk_score?: number;
  timestamp?: string;
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface IncidentsResponse {
  incidents: Incident[];
  page: number;
  total: number;
}

export interface Incident {
  id: string;
  type?: string;
  tier?: number;
  risk_score?: number;
  status?: string;
  created_at?: string;
  description?: string;
  event_id?: string;
  // Explainability fields
  matched_rules?: string[];
  policy_citations?: string[];
  confidence?: number;
  explanation?: string;
  blast_radius?: string;
  [key: string]: unknown;
}

export interface AuditEntry {
  id?: string;
  event_id?: string;
  action?: string;
  actor?: string;
  timestamp?: string;
  hash?: string;
  [key: string]: unknown;
}

export interface AuditResponse {
  entries: AuditEntry[];
  page: number;
  total: number;
}

export interface ActionResponse {
  incident_id: string;
  action: string;
  status: string;
}

export interface SensorInfo {
  id: string;
  name: string;
  description: string;
  listen_addr: string;
  subsystems: string[];
  config: Record<string, unknown>;
}

export interface SensorsResponse {
  sensors: SensorInfo[];
}

export interface SystemStats {
  cpu_util_pct: number;   // 0–100, or -1 if not yet available
  cpu_cores: number;
  load_avg_1m: number;
  load_avg_5m: number;
  load_avg_15m: number;
  mem_total_mb: number;
  mem_used_mb: number;
  mem_used_pct: number;
  mem_apps: { name: string; mem_mb: number }[];
  sampled_at: string;
}

export interface SummaryRequest {
  total_events: number;
  total_incidents: number;
  cpu_util_pct: number;
  mem_used_pct: number;
  load_avg_1m: number;
  top_event_types: { type: string; count: number }[];
  tier_breakdown: { tier: string; count: number }[];
  incident_statuses: { status: string; count: number }[];
  // HostGuard
  host_total_events: number;
  host_threat_events: number;
  host_unique_hosts: number;
  host_active_rules: number;
  // AgentGuard
  agent_total_agents: number;
  agent_active_agents: number;
  agent_suspended_count: number;
  agent_quarantine_count: number;
  agent_total_threats: number;
  // ModelGuard
  model_total_calls: number;
  model_blocked_calls: number;
  model_avg_latency_ms: number;
  model_avg_confidence: number;
  model_risk_breakdown: { label: string; count: number }[];
  // CommsGuard
  comms_total_events: number;
  comms_total_threats: number;
  comms_top_event_types: { type: string; count: number }[];
  // Threat / anomaly breakdowns per module
  host_top_event_types: { type: string; count: number }[];
  agent_top_event_types: { type: string; count: number }[];
}

export interface SummaryResponse {
  summary: string;
  provider: string;
  generated_at: string;
  cache_hit: boolean;
}

export type IncidentDetailResponse = Incident;

// ─── AgentGuard types ────────────────────────────────────────────────────────

export interface AgentRecord {
  agent_id: string;
  agent_name: string;
  agent_type: string;
  approved_tools: string[];
  approved_domains: string[];
  token_quota: number;
  call_quota: number;
  suspended: boolean;
  quarantined: boolean;
  registered_at: string;
  last_activity_at?: string;
  threat_count: number;
  action_count: number;
}

export interface AgentEventTypeStat {
  type: string;
  count: number;
}

export interface AgentStatsResponse {
  total_agents: number;
  active_agents: number;
  suspended_count: number;
  quarantine_count: number;
  total_threats: number;
  total_actions: number;
  event_types: AgentEventTypeStat[];
  period: string;
  computed_at: string;
}

export interface AgentListResponse {
  agents: AgentRecord[];
  total: number;
}

export interface AgentEventsResponse {
  events: Record<string, unknown>[];
  total: number;
  page: number;
  page_size: number;
}

export interface AgentRule {
  id: string;
  name: string;
  description: string;
  severity: string;
  tier: string;
  responses: string[];
  enabled: boolean;
}

export interface AgentRulesResponse {
  rules: AgentRule[];
  total: number;
}

export interface AgentActionResponse {
  agent_id: string;
  suspended?: boolean;
  unsuspended?: boolean;
  quarantined?: boolean;
}

// ─── CommsGuard types ─────────────────────────────────────────────────────────

export interface CommsChannel {
  id: string;
  name: string;
  icon: string;
  webhook_path: string;
  description: string;
  configured: boolean;
  enabled?: boolean;
  message_count?: number;
  threat_count?: number;
  last_event?: string;
}

export interface CommsEventTypeStat {
  type: string;
  count: number;
}

export interface CommsStatsResponse {
  channels: CommsChannel[];
  event_types: CommsEventTypeStat[];
  total_events: number;
  total_threats: number;
  period: string;
  computed_at: string;
}

export interface CommsChannelsResponse {
  channels: CommsChannel[];
}

export interface CommsEventsResponse {
  events: Event[];
  page: number;
  page_size: number;
  total: number;
}

export interface CommsChannelConfigItem {
  id: string;
  enabled: boolean;
  has_webhook_secret: boolean;
  has_verify_token: boolean;
  has_account_sid: boolean;
  has_bearer_token: boolean;
  has_bot_token: boolean;
  webhook_url?: string;
}

export interface CommsConfigResponse {
  channels: CommsChannelConfigItem[];
  enable_content_analysis: boolean;
  bulk_message_threshold: number;
  bulk_message_window_sec: number;
}

// ─── ModelGuard types ────────────────────────────────────────────────────────

export interface ModelCallEntry {
  call_id: string;
  timestamp: string;
  agent_id: string;
  provider: string;
  risk_level: string;
  routing_strategy: string;
  latency_ms: number;
  token_count: number;
  redactions?: string[];
  blocked: boolean;
  input_hash: string;
  output_hash: string;
}

export interface ModelCallAuditResponse {
  entries: ModelCallEntry[];
  total: number;
  page: number;
  page_size: number;
}

export interface KvStat {
  label: string;
  count: number;
}

export interface ModelGuardStatsResponse {
  total_calls: number;
  blocked_calls: number;
  avg_latency_ms: number;
  avg_token_count: number;
  avg_confidence: number;
  provider_breakdown: KvStat[];
  strategy_breakdown: KvStat[];
  risk_breakdown: KvStat[];
  active_provider: string;
  period: string;
  computed_at: string;
}

export interface ProviderHealthEntry {
  id: string;
  name: string;
  healthy: boolean;
  latency_ms: number;
  last_checked: string;
  error?: string;
}

export interface ModelGuardProvidersResponse {
  providers: ProviderHealthEntry[];
}

export interface GuardrailConfig {
  block_on_injection: boolean;
  redact_credentials: boolean;
  redact_pii: boolean;
  max_prompt_length: number;
  min_confidence: number;
  rate_limit_rpm: number;
}

export interface GuardrailUpdateResponse {
  status: string;
  config: GuardrailConfig;
}

export interface CommsChannelUpdate {
  id: string;
  enabled: boolean;
  webhook_secret?: string;
  verify_token?: string;
  account_sid?: string;
  bearer_token?: string;
  bot_token?: string;
  webhook_url?: string;
}

// ─── WhatsApp Live Session types (QR-based multi-device) ───────────────────

export interface WAStatus {
  state: 'disconnected' | 'connecting' | 'qr_ready' | 'connected';
  phone?: string;
  name?: string;
  connected_since?: string;
  message_count: number;
}

export interface WAQRData {
  state: 'disconnected' | 'connecting' | 'qr_ready' | 'connected';
  qr_image?: string;   // data:image/png;base64,...
  expires_at?: string; // RFC3339
}

export interface WAMessage {
  id: string;
  chat: string;
  sender: string;
  content: string;
  timestamp: string;
  has_media: boolean;
  from_me: boolean;
  is_group: boolean;
  is_flagged: boolean;
  threats: string[];
}

export interface WAMessagesResponse {
  messages: WAMessage[];
  total: number;
}

// ─── Telegram Bot Session types ───────────────────────────────────────────────

export interface TGStatus {
  state: 'disconnected' | 'connecting' | 'polling';
  bot_username?: string;
  bot_id?: number;
  connected_since?: string; // RFC3339
  message_count: number;
}

export interface TGMessage {
  id: string;
  chat_id: number;
  chat_title?: string;
  sender: string;
  username?: string;
  content: string;
  timestamp: string;
  is_group: boolean;
  is_flagged: boolean;
  threats: string[];
}

export interface TGMessagesResponse {
  messages: TGMessage[];
  total: number;
}

// ─── HostGuard types ─────────────────────────────────────────────────────────

export interface HostEventTypeStat {
  type: string;
  count: number;
}

export interface HostStatsResponse {
  total_events: number;
  threat_events: number;
  unique_hosts: number;
  active_rules: number;
  event_types: HostEventTypeStat[];
  tier_breakdown: Record<string, number>;
  period: string;
  computed_at: string;
}

export interface HostEventsResponse {
  events: Event[];
  total: number;
  page: number;
  page_size: number;
}

export interface HostRule {
  id: string;
  name: string;
  description: string;
  severity: string;
  tier: string;
  responses: string[];
  enabled: boolean;
}

export interface HostRulesResponse {
  rules: HostRule[];
  total: number;
}

// ─── NetworkGuard types ───────────────────────────────────────────────────────

export interface NetEventTypeStat {
  type: string;
  count: number;
}

export interface NetStatsResponse {
  total_events: number;
  threat_events: number;
  unique_sources: number;
  blocked_flows: number;
  active_rules: number;
  event_types: NetEventTypeStat[];
  protocol_breakdown: Record<string, number>;
  tier_breakdown: Record<string, number>;
  period: string;
  computed_at: string;
}

export interface NetEventsResponse {
  events: Event[];
  total: number;
  page: number;
  page_size: number;
}

export interface NetRule {
  id: string;
  name: string;
  description: string;
  severity: string;
  tier: string;
  responses: string[];
  enabled: boolean;
}

export interface NetRulesResponse {
  rules: NetRule[];
  total: number;
}

// ─── Config API types ────────────────────────────────────────────────────────

export interface StatusResponse {
  status: string;
  [key: string]: unknown;
}

// ─── RBAC user types ─────────────────────────────────────────────────────────

export interface UserRecord {
  username: string;
  role: 'viewer' | 'analyst' | 'operator' | 'admin';
  created_at?: string;
}

// ─── Webhook types ───────────────────────────────────────────────────────────

export interface WebhookConfig {
  id: string;
  name: string;
  url: string;
  min_tier: number;
  format: 'slack' | 'pagerduty' | 'generic';
  enabled: boolean;
  created_at?: string;
}

// ─── Supply-chain types ───────────────────────────────────────────────────────

export interface SupplyChainEvent {
  id: string;
  timestamp: string;
  host: string;
  installer: string;
  package_name: string;
  version?: string;
  risk_score: number;
  risk_label: string;
  flags?: string[];
}

export interface SupplyChainResponse {
  events: SupplyChainEvent[];
  page: number;
  total: number;
  high_risk: number;
  installers: Record<string, number>;
}

export interface SupplyChainStats {
  total: number;
  high_risk: number;
  installers: Record<string, number>;
}

// ─── Baseline types ───────────────────────────────────────────────────────────

export interface BaselineEntityStats {
  key: string;
  mean: number;
  std_dev: number;
  sample_count: number;
  last_update: string;
}


export interface RuleOverride {
  enabled: boolean;
  severity?: string;
  tier?: string;
}

export interface HostSensorConfig {
  scan_interval_secs: number;
  cpu_alert_threshold_pct: number;
  mem_alert_threshold_mb: number;
}

export interface ConfiguredHostRule extends HostRule {
  // same as HostRule but with overrides applied
}

export interface HostGuardConfigResponse {
  sensor_config: HostSensorConfig;
  rules: ConfiguredHostRule[];
}

export interface ConfiguredAgentRule extends AgentRule {
  // same as AgentRule but with overrides applied
}

export interface AgentGuardConfigResponse {
  rules: ConfiguredAgentRule[];
}

export interface AgentToolConfig {
  agent_id: string;
  agent_name: string;
  approved_tools: string[];
  approved_domains: string[];
  token_quota: number;
  call_quota: number;
  created_at?: string;
}

export interface AgentToolsResponse {
  tools: AgentToolConfig[];
}

export interface CommsChannelConfigPatch {
  enabled: boolean;
  webhook_secret?: string;
  verify_token?: string;
  account_sid?: string;
  bearer_token?: string;
  bot_token?: string;
  webhook_url?: string;
}

export interface CommsChannelConfigEntry {
  enabled: boolean;
  webhook_secret?: string;
  verify_token?: string;
  account_sid?: string;
  bearer_token?: string;
  bot_token?: string;
  webhook_url?: string;
}

export interface CommsGlobalConfig {
  content_analysis?: boolean;
  bulk_threshold?: number;
  bulk_window_sec?: number;
}

export interface CommsGuardConfigResponse {
  content_analysis: boolean;
  bulk_threshold: number;
  bulk_window_sec: number;
  channels: Record<string, CommsChannelConfigEntry>;
}

export interface KPITierStat { tier: string; count: number }
export interface KPIRiskBand { label: string; count: number }
export interface KPIIncidentStatus { status: string; count: number }
export interface KPIGuardThreats { guard: string; count: number; color: string }
export interface KPIStats {
  total_events: number;
  total_incidents: number;
  tier_breakdown: KPITierStat[];
  risk_breakdown: KPIRiskBand[];
  incident_statuses: KPIIncidentStatus[];
  guard_threats: KPIGuardThreats[];
  computed_at: string;
}

export interface PolicyRule {
  id: string;
  description: string;
  action: 'block' | 'require_approval' | 'allow';
  policy_ref: string;
  enabled: boolean;
  conditions: string[];
}

export type PolicyRuleInput = Omit<PolicyRule, 'id'> & { id?: string };

export interface PoliciesResponse {
  policies: PolicyRule[];
}

export interface CreatePolicyResponse {
  status: string;
  id: string;
}

// ─── API functions ───────────────────────────────────────────────────────────

export const api = {
  health: () => get<HealthResponse>('/health'),
  events: (page?: number) => get<EventsResponse>(`/api/v1/events${page !== undefined ? `?page=${page}` : ''}`),
  incidents: (page?: number) => get<IncidentsResponse>(`/api/v1/incidents${page !== undefined ? `?page=${page}` : ''}`),
  incident: (id: string) => get<IncidentDetailResponse>(`/api/v1/incidents/${encodeURIComponent(id)}`),
  audit: (eventId?: string, page?: number) =>
    get<AuditResponse>(`/api/v1/audit${buildQuery({ event_id: eventId, page: page !== undefined ? String(page) : undefined })}`),
  incidentAction: (id: string, action: 'approve' | 'deny' | 'override') =>
    post<ActionResponse>(`/api/v1/incidents/${encodeURIComponent(id)}/${action}`),
  sensors: () => get<SensorsResponse>('/api/v1/sensors'),
  systemStats: () => get<SystemStats>('/api/v1/system/stats'),
  summary: (body: SummaryRequest) => postJSON<SummaryResponse>('/api/v1/summary', body),
  login: (username: string, password: string) =>
    postJSON<LoginResponse>('/api/v1/login', { username, password }),

  // AgentGuard endpoints
  agentStats: () => get<AgentStatsResponse>('/api/v1/agentguard/stats'),
  agentList: () => get<AgentListResponse>('/api/v1/agentguard/agents'),
  agentDetail: (id: string) => get<AgentRecord>(`/api/v1/agentguard/agents/${encodeURIComponent(id)}`),
  agentEvents: (agentId?: string, eventType?: string, page?: number) =>
    get<AgentEventsResponse>(
      `/api/v1/agentguard/events${buildQuery({ agent_id: agentId, event_type: eventType, page: page !== undefined ? String(page) : undefined })}`,
    ),
  agentRules: () => get<AgentRulesResponse>('/api/v1/agentguard/rules'),
  suspendAgent: (id: string) => post<AgentActionResponse>(`/api/v1/agentguard/agents/${encodeURIComponent(id)}/suspend`),
  unsuspendAgent: (id: string) => post<AgentActionResponse>(`/api/v1/agentguard/agents/${encodeURIComponent(id)}/unsuspend`),
  quarantineAgent: (id: string) => post<AgentActionResponse>(`/api/v1/agentguard/agents/${encodeURIComponent(id)}/quarantine`),

  // CommsGuard endpoints
  commsStats: () => get<CommsStatsResponse>('/api/v1/commsguard/stats'),
  commsChannels: () => get<CommsChannelsResponse>('/api/v1/commsguard/channels'),
  commsEvents: (channel?: string, page?: number) =>
    get<CommsEventsResponse>(
      `/api/v1/commsguard/events${buildQuery({ channel, page: page !== undefined ? String(page) : undefined })}`,
    ),
  commsConfig: () => get<CommsConfigResponse>('/api/v1/commsguard/config'),
  updateCommsChannel: (channel: CommsChannelUpdate) =>
    postJSON<{ status: string }>('/api/v1/commsguard/config', { channel }),
  // WhatsApp live session (QR-based connection)
  waStatus: () => get<WAStatus>('/api/v1/commsguard/whatsapp/status'),
  waQR: () => get<WAQRData>('/api/v1/commsguard/whatsapp/qr'),
  waMessages: () => get<WAMessagesResponse>('/api/v1/commsguard/whatsapp/messages'),
  waConnect: () => post<{ status: string }>('/api/v1/commsguard/whatsapp/connect'),
  waLogout: () => post<{ status: string }>('/api/v1/commsguard/whatsapp/logout'),
  // Telegram bot session
  tgStatus: () => get<TGStatus>('/api/v1/commsguard/telegram/status'),
  tgMessages: () => get<TGMessagesResponse>('/api/v1/commsguard/telegram/messages'),
  tgConnect: () => post<{ status: string }>('/api/v1/commsguard/telegram/connect'),
  tgDisconnect: () => post<{ status: string }>('/api/v1/commsguard/telegram/disconnect'),

  // ModelGuard endpoints
  modelGuardStats: () => get<ModelGuardStatsResponse>('/api/v1/modelguard/stats'),
  modelGuardAudit: (provider?: string, riskLevel?: string, page?: number) =>
    get<ModelCallAuditResponse>(
      `/api/v1/modelguard/audit${buildQuery({
        provider,
        risk_level: riskLevel,
        page: page !== undefined ? String(page) : undefined,
      })}`,
    ),
  modelGuardProviders: () => get<ModelGuardProvidersResponse>('/api/v1/modelguard/providers'),
  modelGuardGuardrails: () => get<GuardrailConfig>('/api/v1/modelguard/guardrails'),
  updateModelGuardGuardrails: (cfg: GuardrailConfig) =>
    postJSON<GuardrailUpdateResponse>('/api/v1/modelguard/guardrails', cfg),

  // HostGuard endpoints
  hostGuardStats: () => get<HostStatsResponse>('/api/v1/hostguard/stats'),
  hostGuardEvents: (eventType?: string, hostname?: string, page?: number) =>
    get<HostEventsResponse>(
      `/api/v1/hostguard/events${buildQuery({
        event_type: eventType,
        hostname,
        page: page !== undefined ? String(page) : undefined,
      })}`,
    ),
  hostGuardRules: () => get<HostRulesResponse>('/api/v1/hostguard/rules'),

  // NetworkGuard endpoints
  networkGuardStats: () => get<NetStatsResponse>('/api/v1/networkguard/stats'),
  networkGuardEvents: (eventType?: string, sourceIp?: string, direction?: string, page?: number) =>
    get<NetEventsResponse>(
      `/api/v1/networkguard/events${buildQuery({
        event_type: eventType,
        source_ip: sourceIp,
        direction,
        page: page !== undefined ? String(page) : undefined,
      })}`,
    ),
  networkGuardRules: () => get<NetRulesResponse>('/api/v1/networkguard/rules'),

  // ── Config API ──────────────────────────────────────────────────────────────

  // HostGuard config
  configHostGuard: () => get<HostGuardConfigResponse>('/api/v1/config/hostguard'),
  updateHostGuardSensor: (cfg: HostSensorConfig) =>
    putJSON<StatusResponse>('/api/v1/config/hostguard', cfg),
  updateHostGuardRule: (id: string, override: RuleOverride) =>
    putJSON<StatusResponse>(`/api/v1/config/hostguard/rules/${encodeURIComponent(id)}`, override),

  // AgentGuard config
  configAgentGuard: () => get<AgentGuardConfigResponse>('/api/v1/config/agentguard'),
  updateAgentGuardRule: (id: string, override: RuleOverride) =>
    putJSON<StatusResponse>(`/api/v1/config/agentguard/rules/${encodeURIComponent(id)}`, override),
  listAgentTools: () => get<AgentToolsResponse>('/api/v1/config/agentguard/tools'),
  createAgentTool: (cfg: AgentToolConfig) =>
    postJSON<StatusResponse>('/api/v1/config/agentguard/tools', cfg),
  updateAgentTool: (id: string, cfg: Partial<AgentToolConfig>) =>
    putJSON<StatusResponse>(`/api/v1/config/agentguard/tools/${encodeURIComponent(id)}`, cfg),
  deleteAgentTool: (id: string) =>
    del<StatusResponse>(`/api/v1/config/agentguard/tools/${encodeURIComponent(id)}`),

  // CommsGuard config
  configCommsGuard: () => get<CommsGuardConfigResponse>('/api/v1/config/commsguard'),
  updateCommsGuardGlobal: (cfg: CommsGlobalConfig) =>
    putJSON<StatusResponse>('/api/v1/config/commsguard', cfg),
  updateCommsGuardChannel: (id: string, cfg: CommsChannelConfigPatch) =>
    putJSON<StatusResponse>(`/api/v1/config/commsguard/channels/${encodeURIComponent(id)}`, cfg),

  // ModelGuard config
  configModelGuard: () => get<GuardrailConfig>('/api/v1/config/modelguard'),
  updateModelGuardConfig: (cfg: GuardrailConfig) =>
    putJSON<StatusResponse>('/api/v1/config/modelguard', cfg),

  // Policies config
  listPolicies: () => get<PoliciesResponse>('/api/v1/config/policies'),
  createPolicy: (rule: PolicyRuleInput) =>
    postJSON<CreatePolicyResponse>('/api/v1/config/policies', rule),
  updatePolicy: (id: string, rule: PolicyRuleInput) =>
    putJSON<StatusResponse>(`/api/v1/config/policies/${encodeURIComponent(id)}`, rule),
  deletePolicy: (id: string) =>
    del<StatusResponse>(`/api/v1/config/policies/${encodeURIComponent(id)}`),

  // Account management
  updateAccount: (currentPassword: string, newUsername: string, newPassword: string) =>
    putJSON<{ username: string }>('/api/v1/account', {
      current_password: currentPassword,
      new_username: newUsername,
      new_password: newPassword,
    }),

  // ── User management (admin only) ───────────────────────────────────────────
  listUsers: () => get<{ users: UserRecord[] }>('/api/v1/users'),
  createUser: (username: string, password: string, role: string) =>
    postJSON<{ username: string }>('/api/v1/users', { username, password, role }),
  updateUser: (username: string, data: { role?: string; new_password?: string }) =>
    putJSON<{ username: string }>(`/api/v1/users/${encodeURIComponent(username)}`, data),
  deleteUser: (username: string) =>
    del<StatusResponse>(`/api/v1/users/${encodeURIComponent(username)}`),

  // ── Webhook configuration (operator+) ──────────────────────────────────────
  listWebhooks: () => get<{ webhooks: WebhookConfig[] }>('/api/v1/config/webhooks'),
  createWebhook: (wh: Omit<WebhookConfig, 'id' | 'created_at'>) =>
    postJSON<WebhookConfig>('/api/v1/config/webhooks', wh),
  updateWebhook: (id: string, wh: Partial<WebhookConfig>) =>
    putJSON<WebhookConfig>(`/api/v1/config/webhooks/${encodeURIComponent(id)}`, wh),
  deleteWebhook: (id: string) =>
    del<StatusResponse>(`/api/v1/config/webhooks/${encodeURIComponent(id)}`),

  // ── Supply Chain Guard ──────────────────────────────────────────────────────
  supplyChain: (page?: number) =>
    get<SupplyChainResponse>(`/api/v1/supplychain${page ? `?page=${page}` : ''}`),
  supplyChainStats: () => get<SupplyChainStats>('/api/v1/supplychain/stats'),

  // ── Baseline analytics ──────────────────────────────────────────────────────
  baselineStats: () => get<{ entities: BaselineEntityStats[] }>('/api/v1/baseline'),

  // ── Aggregated KPI stats (full-store sweep) ─────────────────────────────────
  kpiStats: () => get<KPIStats>('/api/v1/stats/kpi'),
};
