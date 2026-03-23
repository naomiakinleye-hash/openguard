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
  type?: string;
  source?: string;
  tier?: number;
  risk_score?: number;
  timestamp?: string;
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

export interface ModelProvider {
  id: string;
  name: string;
  available: boolean;    // true = user has connected this provider
  uses_oauth: boolean;   // true = OAuth2 sign-in flow; false = API key entry form
}

export interface ModelsResponse {
  active: string;
  providers: ModelProvider[];
}

export interface SetActiveModelResponse {
  active: string;
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
}

export interface SummaryResponse {
  summary: string;
  provider: string;
  generated_at: string;
  cache_hit: boolean;
}

export type IncidentDetailResponse = Incident;

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

// ─── API functions ───────────────────────────────────────────────────────────

export const api = {
  health: () => get<HealthResponse>('/health'),
  events: (page?: number) => get<EventsResponse>(`/api/v1/events${page !== undefined ? `?page=${page}` : ''}`),
  incidents: (page?: number) => get<IncidentsResponse>(`/api/v1/incidents${page !== undefined ? `?page=${page}` : ''}`),
  incident: (id: string) => get<IncidentDetailResponse>(`/api/v1/incidents/${encodeURIComponent(id)}`),
  audit: (eventId?: string) =>
    get<AuditResponse>(`/api/v1/audit${eventId ? `?event_id=${encodeURIComponent(eventId)}` : ''}`),
  incidentAction: (id: string, action: 'approve' | 'deny' | 'override') =>
    post<ActionResponse>(`/api/v1/incidents/${encodeURIComponent(id)}/${action}`),
  sensors: () => get<SensorsResponse>('/api/v1/sensors'),
  models: () => get<ModelsResponse>('/api/v1/models'),
  setActiveModel: (provider: string) =>
    postJSON<SetActiveModelResponse>('/api/v1/models/active', { provider }),
  oauthStart: (provider: string) =>
    get<{ auth_url: string }>(`/api/v1/models/oauth/start?provider=${encodeURIComponent(provider)}`),
  saveCredential: (provider: string, credential: string) =>
    postJSON<{ status: string; provider: string }>('/api/v1/models/credentials', { provider, credential }),
  deleteCredential: (provider: string) =>
    del<{ status: string; provider: string }>(`/api/v1/models/credentials?provider=${encodeURIComponent(provider)}`),
  systemStats: () => get<SystemStats>('/api/v1/system/stats'),
  summary: (body: SummaryRequest) => postJSON<SummaryResponse>('/api/v1/summary', body),
  login: (username: string, password: string) =>
    postJSON<LoginResponse>('/api/v1/login', { username, password }),

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
};
