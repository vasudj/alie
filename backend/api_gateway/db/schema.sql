PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS detected_apis (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    risk_score REAL NOT NULL DEFAULT 0,
    detection_reason TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    blocked_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'safe',
    source_ip TEXT,
    user_agent TEXT,
    UNIQUE(endpoint, method)
);

CREATE TABLE IF NOT EXISTS request_events (
    request_id TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    ip TEXT NOT NULL,
    headers_summary TEXT,
    payload_size INTEGER NOT NULL DEFAULT 0,
    response_status INTEGER NOT NULL DEFAULT 0,
    risk_score REAL NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS zombie_endpoints (
    endpoint TEXT PRIMARY KEY,
    detection_reason TEXT NOT NULL DEFAULT '',
    first_detected TEXT NOT NULL,
    last_detected TEXT NOT NULL,
    hit_count INTEGER NOT NULL DEFAULT 0,
    currently_blocked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    endpoint TEXT,
    ip TEXT,
    description TEXT NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ip_intelligence (
    ip TEXT PRIMARY KEY,
    total_requests INTEGER NOT NULL DEFAULT 0,
    suspicious_requests INTEGER NOT NULL DEFAULT 0,
    blocked_requests INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT NOT NULL,
    threat_level TEXT NOT NULL DEFAULT 'LOW'
);

CREATE INDEX IF NOT EXISTS idx_detected_apis_status ON detected_apis(status, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_detected_apis_last_seen ON detected_apis(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_request_events_timestamp ON request_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_request_events_ip ON request_events(ip, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ip_intelligence_blocked ON ip_intelligence(blocked_requests DESC, suspicious_requests DESC);

-- ─────────────────────────────────────────────────────────────
-- Semgrep Static Scanner
-- ─────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS semgrep_scans (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'queued',
    target_path TEXT,
    config TEXT DEFAULT 'auto',
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    findings_count INTEGER DEFAULT 0,
    findings_critical INTEGER DEFAULT 0,
    findings_high INTEGER DEFAULT 0,
    findings_medium INTEGER DEFAULT 0,
    findings_low INTEGER DEFAULT 0,
    error_message TEXT,
    report_path TEXT
);

CREATE TABLE IF NOT EXISTS scan_brain_analyses (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    severity_assessment TEXT,
    categorized_findings TEXT,
    remediation_priorities TEXT,
    summary TEXT,
    raw_response TEXT,
    FOREIGN KEY (scan_id) REFERENCES semgrep_scans(id)
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON semgrep_scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_created ON semgrep_scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_analysis_scan ON scan_brain_analyses(scan_id);
