"""SQLite metadata helpers for request intelligence, alerts, and zombie APIs."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Iterable, Optional

from core.config import settings

from .database import cleanup as _cleanup, execute, fetchall, fetchone, init_database

_STATUS_ORDER = {"safe": 0, "suspicious": 1, "zombie": 2, "blocked": 3}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def _normalize_status(status: str | None) -> str:
    status = (status or "safe").lower()
    return status if status in _STATUS_ORDER else "safe"


def _merge_status(current: str, incoming: str) -> str:
    return incoming if _STATUS_ORDER.get(incoming, 0) >= _STATUS_ORDER.get(current, 0) else current


def _summarize_headers(headers: Dict[str, Any] | None) -> str:
    if not headers:
        return "{}"
    interesting_keys = (
        "user-agent",
        "content-type",
        "accept",
        "authorization",
        "x-api-key",
        "api-key",
        "x-service-token",
        "x-zombie-bootstrap",
        "x-forwarded-for",
        "x-real-ip",
    )
    summary: Dict[str, Any] = {}
    for key in interesting_keys:
        value = headers.get(key) or headers.get(key.title()) or headers.get(key.upper())
        if value:
            summary[key] = value if key not in {"authorization", "x-api-key", "api-key", "x-service-token"} else "present"
    return json.dumps(summary, default=str)


async def init_sqlite_storage() -> None:
    await init_database()
    if settings.SQLITE_CLEANUP_ON_STARTUP:
        await cleanup_old_records()


async def cleanup_old_records() -> None:
    cutoff = _now()
    retention_seconds = max(settings.SQLITE_RETENTION_DAYS, 1) * 86400
    cutoff_epoch = time.time() - retention_seconds
    cutoff_ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(cutoff_epoch))
    await execute("DELETE FROM request_events WHERE timestamp < ?", (cutoff_ts,))
    await execute("DELETE FROM alerts WHERE timestamp < ?", (cutoff_ts,))
    await _cleanup()


async def save_request_event(
    *,
    request_id: str,
    endpoint: str,
    method: str,
    ip: str,
    headers_summary: Dict[str, Any] | str | None,
    payload_size: int,
    response_status: int,
    risk_score: float,
    blocked: bool,
    timestamp: str | None = None,
) -> None:
    headers_json = headers_summary if isinstance(headers_summary, str) else json.dumps(headers_summary or {}, default=str)
    await execute(
        """
        INSERT INTO request_events (
            request_id, endpoint, method, ip, headers_summary, payload_size,
            response_status, risk_score, blocked, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(request_id) DO UPDATE SET
            endpoint = excluded.endpoint,
            method = excluded.method,
            ip = excluded.ip,
            headers_summary = excluded.headers_summary,
            payload_size = excluded.payload_size,
            response_status = excluded.response_status,
            risk_score = excluded.risk_score,
            blocked = excluded.blocked,
            timestamp = excluded.timestamp
        """,
        (
            request_id,
            endpoint,
            method,
            ip,
            headers_json,
            int(payload_size),
            int(response_status),
            float(risk_score),
            1 if blocked else 0,
            timestamp or _now(),
        ),
    )


async def save_zombie_endpoint(
    *,
    endpoint: str,
    detection_reason: str,
    blocked: bool = False,
    timestamp: str | None = None,
) -> None:
    existing = await fetchone("SELECT * FROM zombie_endpoints WHERE endpoint = ?", (endpoint,))
    ts = timestamp or _now()
    if existing:
        await execute(
            """
            UPDATE zombie_endpoints
            SET detection_reason = ?,
                last_detected = ?,
                hit_count = hit_count + 1,
                currently_blocked = ?
            WHERE endpoint = ?
            """,
            (
                detection_reason or existing["detection_reason"],
                ts,
                1 if blocked else existing["currently_blocked"],
                endpoint,
            ),
        )
        return
    await execute(
        """
        INSERT INTO zombie_endpoints (
            endpoint, detection_reason, first_detected, last_detected, hit_count, currently_blocked
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            endpoint,
            detection_reason,
            ts,
            ts,
            1,
            1 if blocked else 0,
        ),
    )


async def save_detected_api(
    *,
    endpoint: str,
    method: str,
    risk_score: float,
    detection_reason: str,
    status: str,
    source_ip: str | None = None,
    user_agent: str | None = None,
    blocked: bool = False,
    timestamp: str | None = None,
) -> None:
    ts = timestamp or _now()
    status = _normalize_status(status)
    existing = await fetchone(
        "SELECT * FROM detected_apis WHERE endpoint = ? AND method = ?",
        (endpoint, method),
    )
    if existing:
        merged_status = _merge_status(existing["status"], status)
        await execute(
            """
            UPDATE detected_apis
            SET risk_score = MAX(risk_score, ?),
                detection_reason = ?,
                last_seen = ?,
                request_count = request_count + 1,
                blocked_count = blocked_count + ?,
                status = ?,
                source_ip = COALESCE(?, source_ip),
                user_agent = COALESCE(?, user_agent)
            WHERE endpoint = ? AND method = ?
            """,
            (
                float(risk_score),
                detection_reason,
                ts,
                1 if blocked else 0,
                merged_status,
                source_ip,
                user_agent,
                endpoint,
                method,
            ),
        )
    else:
        await execute(
            """
            INSERT INTO detected_apis (
                endpoint, method, risk_score, detection_reason, first_seen, last_seen,
                request_count, blocked_count, status, source_ip, user_agent
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                endpoint,
                method,
                float(risk_score),
                detection_reason,
                ts,
                ts,
                1,
                1 if blocked else 0,
                status,
                source_ip,
                user_agent,
            ),
        )

    if status in {"zombie", "blocked"} or blocked:
        await save_zombie_endpoint(endpoint=endpoint, detection_reason=detection_reason or status, blocked=blocked, timestamp=ts)


async def save_alert(
    *,
    alert_type: str,
    severity: str,
    endpoint: str | None,
    ip: str | None,
    description: str,
    timestamp: str | None = None,
) -> None:
    await execute(
        """
        INSERT INTO alerts (alert_type, severity, endpoint, ip, description, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (alert_type, severity, endpoint, ip, description, timestamp or _now()),
    )


async def update_ip_intelligence(
    *,
    ip: str,
    suspicious_requests: int = 0,
    blocked_requests: int = 0,
    threat_level: str | None = None,
    timestamp: str | None = None,
    total_requests: int = 1,
) -> None:
    ts = timestamp or _now()
    existing = await fetchone("SELECT * FROM ip_intelligence WHERE ip = ?", (ip,))
    if existing:
        merged_threat = threat_level or existing["threat_level"]
        await execute(
            """
            UPDATE ip_intelligence
            SET total_requests = total_requests + ?,
                suspicious_requests = suspicious_requests + ?,
                blocked_requests = blocked_requests + ?,
                last_seen = ?,
                threat_level = ?
            WHERE ip = ?
            """,
            (
                total_requests,
                suspicious_requests,
                blocked_requests,
                ts,
                merged_threat,
                ip,
            ),
        )
    else:
        await execute(
            """
            INSERT INTO ip_intelligence (
                ip, total_requests, suspicious_requests, blocked_requests, last_seen, threat_level
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                ip,
                total_requests,
                suspicious_requests,
                blocked_requests,
                ts,
                threat_level or "LOW",
            ),
        )


async def get_top_zombie_apis(limit: int = 10) -> list[dict[str, Any]]:
    return await fetchall(
        """
        SELECT endpoint, method, risk_score, detection_reason, first_seen, last_seen,
               request_count, blocked_count, status, source_ip, user_agent
        FROM detected_apis
        WHERE status IN ('zombie', 'blocked', 'suspicious')
        ORDER BY risk_score DESC, blocked_count DESC, request_count DESC, last_seen DESC
        LIMIT ?
        """,
        (limit,),
    )


async def get_most_blocked_ips(limit: int = 10) -> list[dict[str, Any]]:
    return await fetchall(
        """
        SELECT ip, total_requests, suspicious_requests, blocked_requests, last_seen, threat_level
        FROM ip_intelligence
        ORDER BY blocked_requests DESC, suspicious_requests DESC, total_requests DESC
        LIMIT ?
        """,
        (limit,),
    )


async def get_recent_alerts(limit: int = 50) -> list[dict[str, Any]]:
    return await fetchall(
        """
        SELECT alert_type, severity, endpoint, ip, description, timestamp
        FROM alerts
        ORDER BY timestamp DESC, id DESC
        LIMIT ?
        """,
        (limit,),
    )


async def get_zombie_endpoints(limit: int = 100) -> list[dict[str, Any]]:
    return await fetchall(
        """
        SELECT endpoint, detection_reason, first_detected, last_detected, hit_count, currently_blocked
        FROM zombie_endpoints
        ORDER BY currently_blocked DESC, hit_count DESC, last_detected DESC
        LIMIT ?
        """,
        (limit,),
    )


async def get_top_risk_apis(limit: int = 10) -> list[dict[str, Any]]:
    return await fetchall(
        """
        SELECT endpoint, method, risk_score, detection_reason, first_seen, last_seen,
               request_count, blocked_count, status, source_ip, user_agent
        FROM detected_apis
        ORDER BY risk_score DESC, blocked_count DESC, request_count DESC, last_seen DESC
        LIMIT ?
        """,
        (limit,),
    )


async def get_db_stats() -> dict[str, Any]:
    detected = await fetchone("SELECT COUNT(*) AS count FROM detected_apis")
    events = await fetchone("SELECT COUNT(*) AS count FROM request_events")
    zombies = await fetchone("SELECT COUNT(*) AS count FROM zombie_endpoints")
    alerts = await fetchone("SELECT COUNT(*) AS count FROM alerts")
    ips = await fetchone("SELECT COUNT(*) AS count FROM ip_intelligence")
    blocked = await fetchone("SELECT COALESCE(SUM(blocked_count), 0) AS total FROM detected_apis")
    suspicious = await fetchone("SELECT COUNT(*) AS count FROM detected_apis WHERE status = 'suspicious'")
    return {
        "detected_apis": detected["count"] if detected else 0,
        "request_events": events["count"] if events else 0,
        "zombie_endpoints": zombies["count"] if zombies else 0,
        "alerts": alerts["count"] if alerts else 0,
        "ip_intelligence": ips["count"] if ips else 0,
        "blocked_request_total": blocked["total"] if blocked else 0,
        "suspicious_apis": suspicious["count"] if suspicious else 0,
        "retention_days": settings.SQLITE_RETENTION_DAYS,
    }


# ─────────────────────────────────────────────────────────────
# Semgrep Scanner helpers
# ─────────────────────────────────────────────────────────────


async def store_scan(
    *,
    scan_id: str,
    target_path: str | None = None,
    config: str = "auto",
) -> None:
    """Insert a new scan record with status 'queued'."""
    await execute(
        """
        INSERT INTO semgrep_scans (id, status, target_path, config, created_at)
        VALUES (?, 'queued', ?, ?, ?)
        """,
        (scan_id, target_path, config, _now()),
    )


async def update_scan_status(
    scan_id: str,
    status: str,
    *,
    started_at: str | None = None,
    completed_at: str | None = None,
    findings_count: int = 0,
    findings_critical: int = 0,
    findings_high: int = 0,
    findings_medium: int = 0,
    findings_low: int = 0,
    error_message: str | None = None,
    report_path: str | None = None,
) -> None:
    """Update scan status and associated metadata."""
    await execute(
        """
        UPDATE semgrep_scans
        SET status = ?,
            started_at = COALESCE(?, started_at),
            completed_at = COALESCE(?, completed_at),
            findings_count = ?,
            findings_critical = ?,
            findings_high = ?,
            findings_medium = ?,
            findings_low = ?,
            error_message = COALESCE(?, error_message),
            report_path = COALESCE(?, report_path)
        WHERE id = ?
        """,
        (
            status,
            started_at,
            completed_at,
            findings_count,
            findings_critical,
            findings_high,
            findings_medium,
            findings_low,
            error_message,
            report_path,
            scan_id,
        ),
    )


async def store_scan_analysis(scan_id: str, analysis: dict[str, Any]) -> None:
    """Insert a Brain AI analysis record for a scan."""
    await execute(
        """
        INSERT INTO scan_brain_analyses (
            id, scan_id, created_at, severity_assessment,
            categorized_findings, remediation_priorities,
            summary, raw_response
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            analysis.get("id", str(__import__("uuid").uuid4())),
            scan_id,
            analysis.get("created_at", _now()),
            analysis.get("severity_assessment", ""),
            json.dumps(analysis.get("categorized_findings", {}), default=str),
            json.dumps(analysis.get("remediation_priorities", []), default=str),
            analysis.get("summary", ""),
            analysis.get("raw_response", ""),
        ),
    )


async def get_scans(limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
    """List scans ordered by creation time (newest first)."""
    return await fetchall(
        """
        SELECT id, status, target_path, config, created_at, started_at,
               completed_at, findings_count, findings_critical, findings_high,
               findings_medium, findings_low, error_message, report_path
        FROM semgrep_scans
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )


async def get_scan(scan_id: str) -> dict[str, Any] | None:
    """Get a single scan by ID."""
    return await fetchone(
        """
        SELECT id, status, target_path, config, created_at, started_at,
               completed_at, findings_count, findings_critical, findings_high,
               findings_medium, findings_low, error_message, report_path
        FROM semgrep_scans
        WHERE id = ?
        """,
        (scan_id,),
    )


async def get_scan_analysis(scan_id: str) -> dict[str, Any] | None:
    """Get the Brain AI analysis for a scan."""
    row = await fetchone(
        """
        SELECT id, scan_id, created_at, severity_assessment,
               categorized_findings, remediation_priorities,
               summary, raw_response
        FROM scan_brain_analyses
        WHERE scan_id = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (scan_id,),
    )
    if row is None:
        return None
    # Parse JSON fields
    try:
        row["categorized_findings"] = json.loads(row.get("categorized_findings", "{}"))
    except (json.JSONDecodeError, TypeError):
        row["categorized_findings"] = {}
    try:
        row["remediation_priorities"] = json.loads(row.get("remediation_priorities", "[]"))
    except (json.JSONDecodeError, TypeError):
        row["remediation_priorities"] = []
    return row
