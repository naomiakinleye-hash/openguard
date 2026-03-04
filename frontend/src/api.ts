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

export type IncidentDetailResponse = Incident;

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
  login: (username: string, password: string) =>
    postJSON<LoginResponse>('/api/v1/login', { username, password }),
};
