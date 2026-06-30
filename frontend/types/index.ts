// ─────────────────────────────────────────────────────────────────────────────
// ALIE Frontend Type Definitions
// Maps 1-to-1 with the FastAPI / Pydantic backend schemas.
//
// Naming convention:
//   • snake_case fields match the raw JSON keys emitted by FastAPI/Pydantic.
//   • camelCase aliases (suffixed with "FE") are used internally by Redux
//     slices that were built before backend integration. During migration
//     the RTK slice transformers should map snake_case → camelCase.
// ─────────────────────────────────────────────────────────────────────────────

// ─── Generic API wrapper ──────────────────────────────────────────────────────
/** Standard FastAPI JSON envelope returned by all ALIE endpoints. */
export interface ApiResponse<T> {
  success: boolean;
  data: T;
  message?: string;
  /** ISO-8601 timestamp generated server-side */
  generated_at: string;
}

/** Paginated list response (mirrors FastAPI's Page[T] pattern). */
export interface PagedResponse<T> {
  items: T[];
  total: number;
  page: number;
  size: number;
  pages: number;
}

// ─── Telemetry ────────────────────────────────────────────────────────────────
/**
 * Mirrors the Pydantic model `TelemetryEventSchema` on the backend.
 * Primary key is a UUID string.
 */
export interface TelemetryEvent {
  /** UUID primary key */
  id: string;
  /** ISO-8601 datetime string (UTC, e.g. "2026-05-29T10:09:32.579Z") */
  created_at: string;
  /** HTTP method */
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  /** Full request URL / path observed */
  url: string;
  /** Originating client IP address */
  ip: string;
  /** Engine decision */
  action: 'ALLOWED' | 'KILLED' | 'BANNED';
  /** ALIE signature label if a threat was detected; null otherwise */
  threat_signature: string | null;

  // ── camelCase aliases kept for Redux slice compatibility ───────────────
  /** @deprecated Use `created_at`. Will be removed post-migration. */
  timestamp?: string;
  /** @deprecated Use `threat_signature`. Will be removed post-migration. */
  threatSignature?: string;
}

// ─── Asset / Route Inventory ──────────────────────────────────────────────────
/**
 * Mirrors `AssetRouteSchema`.
 */
export interface AssetRoute {
  /** Registered path prefix (e.g. "/srv/api/v1/auth") */
  path: string;
  /** Upstream target route */
  target: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  /** ALIE compliance classification */
  compliance_state: 'SECURE' | 'SHADOW_DRIFT' | 'ZOMBIE_EXCEPTION';
  /** Observed additional latency injected by the ALIE proxy */
  added_latency: string;
  /** Error rate percentage (0–100) */
  error_rate: number;

  // ── camelCase aliases ──────────────────────────────────────────────────
  /** @deprecated Use `compliance_state`. */
  complianceState?: 'SECURE' | 'SHADOW_DRIFT' | 'ZOMBIE_EXCEPTION';
  /** @deprecated Use `added_latency`. */
  addedLatency?: string;
  /** @deprecated Use `error_rate`. */
  errorRate?: number;
}

// ─── TrapNet ──────────────────────────────────────────────────────────────────
/**
 * Mirrors `TrapDeploymentSchema`.
 */
export interface TrapDeployment {
  id: string;
  path: string;
  type: 'Honeypot' | 'Tarpit' | 'Decoy Payload';
  status: 'ACTIVE' | 'TRAPPED' | 'INACTIVE';
  /** ISO-8601 datetime string */
  deployed_at: string;

  // ── camelCase alias ────────────────────────────────────────────────────
  /** @deprecated Use `deployed_at`. */
  deployedAt?: string;
}

// ─── Banned IPs ───────────────────────────────────────────────────────────────
/**
 * Mirrors `BannedIPSchema`.
 */
export interface BannedIP {
  id: string;
  /** ISO-8601 datetime string */
  created_at: string;
  url: string;
  ip: string;
  reason: string;

  // ── camelCase alias ────────────────────────────────────────────────────
  /** @deprecated Use `created_at`. */
  timestamp?: string;
}

// ─── Forensic Payloads ────────────────────────────────────────────────────────
/**
 * Mirrors `ForensicPayloadSchema`.
 * The `payload_data` field accepts arbitrary JSON captured from the decoy trap.
 */
export interface ForensicPayload {
  id: string;
  /** ISO-8601 datetime string */
  created_at: string;
  /** Raw captured HTTP headers as a single string */
  header: string;
  /** Arbitrary captured payload — may be a JSON object or a raw string */
  payload_data: unknown;
  /** ALIE signature label (e.g. "SQLi", "RCE") */
  signature: string;

  // ── camelCase aliases ──────────────────────────────────────────────────
  /** @deprecated Use `created_at`. */
  timestamp?: string;
  /** @deprecated Use `payload_data`. */
  payload?: string;
}

// ─── System Metrics ───────────────────────────────────────────────────────────
/**
 * Mirrors `SystemMetricsSchema`.
 */
export interface SystemMetrics {
  risk_score: number;
  shadow_api_percent: number;
  incident_discovery_time: string;
  added_latency: string;
  threats_neutralized: number;
  total_apis: number;
  active_traps: number;

  // ── camelCase aliases ──────────────────────────────────────────────────
  /** @deprecated Use `risk_score`. */
  riskScore?: number;
  /** @deprecated Use `shadow_api_percent`. */
  shadowApiPercent?: number;
  /** @deprecated Use `incident_discovery_time`. */
  incidentDiscoveryTime?: string;
  /** @deprecated Use `threats_neutralized`. */
  threatsNeutralized?: number;
  /** @deprecated Use `total_apis`. */
  totalApis?: number;
  /** @deprecated Use `active_traps`. */
  activeTraps?: number;
}

// ─── Scan History ─────────────────────────────────────────────────────────────
/**
 * Mirrors `ScanHistoryEntrySchema`.
 */
export interface ScanHistoryEntry {
  id: string;
  /** ISO-8601 datetime string */
  created_at: string;
  scan_target: string;
  total_apis_scanned: number;
  vulnerabilities_found: number;
  engine_status: 'Completed' | 'Running' | 'Failed';

  // ── camelCase aliases ──────────────────────────────────────────────────
  /** @deprecated Use `created_at`. */
  timestamp?: string;
  /** @deprecated Use `scan_target`. */
  scanTarget?: string;
  /** @deprecated Use `total_apis_scanned`. */
  totalApisScanned?: number;
  /** @deprecated Use `vulnerabilities_found`. */
  vulnerabilitiesFound?: number;
  /** @deprecated Use `engine_status`. */
  engineStatus?: 'Completed' | 'Running' | 'Failed';
}

// ─── WebSocket Messages ───────────────────────────────────────────────────────
/** Shape of the JSON frame pushed by the FastAPI WebSocket endpoint. */
export interface WsTelemetryFrame {
  type: 'event' | 'ping' | 'error';
  /** Present when type === 'event' */
  event?: TelemetryEvent;
  /** Present when type === 'error' */
  detail?: string;
}
