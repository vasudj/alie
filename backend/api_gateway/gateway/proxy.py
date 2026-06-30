"""Async reverse proxy for request intake, scoring, forwarding, and response interception."""

from __future__ import annotations

from datetime import datetime, timezone
import asyncio
import json
import time
from uuid import uuid4
from typing import Dict, Optional

import httpx
import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse

from core.config import settings
from db.db_helpers import save_detected_api, save_request_event
from detection.scorer import score_request
from eventbus.redis_bus import incr_counter, mark_zombie_endpoint, push_request_event, record_response_code
from shared.models import RiskResult

log = structlog.get_logger(__name__)

_http_client: Optional[httpx.AsyncClient] = None


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _summarize_headers(headers: Dict[str, str]) -> Dict[str, str]:
    summary = {
        "user-agent": headers.get("user-agent", ""),
        "content-type": headers.get("content-type", ""),
        "accept": headers.get("accept", ""),
        "x-forwarded-for": headers.get("x-forwarded-for", ""),
    }
    if headers.get("authorization"):
        summary["authorization"] = "present"
    if headers.get("x-api-key") or headers.get("api-key"):
        summary["api-key"] = "present"
    if headers.get("x-service-token"):
        summary["x-service-token"] = "present"
    if headers.get("x-zombie-bootstrap"):
        summary["x-zombie-bootstrap"] = headers.get("x-zombie-bootstrap", "")
    return {k: v for k, v in summary.items() if v}


def _risk_status(risk: RiskResult) -> str:
    if risk.blocked:
        return "blocked"
    if risk.primary_reason and "zombie" in risk.primary_reason:
        return "zombie"
    if risk.warned:
        return "suspicious"
    return "safe"


async def _persist_metadata(
    *,
    request_id: str,
    endpoint: str,
    method: str,
    source_ip: str,
    headers_dict: Dict[str, str],
    payload_size: int,
    response_status: int,
    risk: RiskResult,
) -> None:
    timestamp = _timestamp()
    headers_summary = _summarize_headers(headers_dict)
    status = _risk_status(risk)
    reason = risk.primary_reason or ",".join(risk.flags) or status
    await asyncio.gather(
        save_request_event(
            request_id=request_id,
            endpoint=endpoint,
            method=method,
            ip=source_ip,
            headers_summary=headers_summary,
            payload_size=payload_size,
            response_status=response_status,
            risk_score=risk.score,
            blocked=risk.blocked,
            timestamp=timestamp,
        ),
        save_detected_api(
            endpoint=endpoint,
            method=method,
            risk_score=risk.score,
            detection_reason=reason,
            status=status,
            source_ip=source_ip,
            user_agent=headers_dict.get("user-agent", ""),
            blocked=risk.blocked,
            timestamp=timestamp,
        ),
        return_exceptions=False,
    )


def get_http_client() -> httpx.AsyncClient:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(settings.HTTPX_TIMEOUT),
            follow_redirects=True,
            limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
        )
    return _http_client


async def close_http_client() -> None:
    global _http_client
    if _http_client and not _http_client.is_closed:
        await _http_client.aclose()


def resolve_backend(path: str) -> Optional[str]:
    local_paths = (
        "/health", "/status", "/metrics", "/dashboard", "/zombies",
        "/events", "/counters", "/risk/score", "/docs", "/redoc",
    )
    if any(path == item or path.startswith(item + "/") for item in local_paths):
        return None
    if path == "/":
        return settings.BACKEND_BASE_URL

    backend_map = settings.backend_map()
    matches = [(prefix, url) for prefix, url in backend_map.items() if path.startswith(prefix)]
    if matches:
        _, best_url = max(matches, key=lambda t: len(t[0]))
        return best_url
    return settings.BACKEND_BASE_URL


def _forward_headers(headers_dict: Dict[str, str], risk: RiskResult, correlation_id: str) -> Dict[str, str]:
    forward_headers = {
        k: v for k, v in headers_dict.items()
        if k.lower() not in {"host", "transfer-encoding", "connection", "keep-alive", "te", "trailers", "upgrade"}
    }
    forward_headers["x-forwarded-by"] = "zombie-gateway"
    forward_headers["x-risk-score"] = str(risk.score)
    forward_headers["x-risk-verdict"] = risk.verdict()
    if correlation_id:
        forward_headers["x-correlation-id"] = correlation_id
    return forward_headers


async def handle_request(request: Request) -> Response:
    start_ts = time.monotonic()
    path = request.url.path
    method = request.method
    source_ip = request.client.host if request.client else "unknown"
    headers_dict = dict(request.headers)
    query_params = dict(request.query_params)
    correlation_id = getattr(request.state, "correlation_id", "")
    request_id = correlation_id or str(uuid4())
    body = await request.body()

    risk: RiskResult = await score_request(
        path=path,
        method=method,
        source_ip=source_ip,
        headers=headers_dict,
        query_params=query_params,
    )

    await incr_counter("total_requests")

    event_base = {
        "ts": str(time.time()),
        "request_id": request_id,
        "correlation_id": correlation_id,
        "path": path,
        "method": method,
        "source_ip": source_ip,
        "risk_score": risk.score,
        "verdict": risk.verdict(),
        "flags": risk.flags,
        "user_agent": headers_dict.get("user-agent", ""),
        "has_auth": bool(
            headers_dict.get("authorization")
            or headers_dict.get("x-api-key")
            or headers_dict.get("api-key")
            or headers_dict.get("x-service-token")
            or headers_dict.get("x-zombie-bootstrap")
        ),
        "query": query_params,
        "request_bytes": len(body),
    }

    if risk.blocked:
        await incr_counter("blocked_requests")
        await record_response_code(path, 403)
        if risk.primary_reason:
            await mark_zombie_endpoint(path, risk.primary_reason)
        await _persist_metadata(
            request_id=request_id,
            endpoint=path,
            method=method,
            source_ip=source_ip,
            headers_dict=headers_dict,
            payload_size=len(body),
            response_status=403,
            risk=risk,
        )
        await push_request_event({**event_base, "blocked": True})
        return JSONResponse(
            status_code=403,
            content={
                "error": "Request blocked by Zombie Gateway",
                "risk_score": risk.score,
                "flags": risk.flags,
                "verdict": "BLOCKED",
                "correlation_id": correlation_id,
            },
            headers={
                "X-Zombie-Score": str(risk.score),
                "X-Zombie-Verdict": "BLOCKED",
                "X-Correlation-ID": correlation_id,
            },
        )

    upstream_base = resolve_backend(path)
    if upstream_base is None:
        await incr_counter("unroutable_requests")
        return JSONResponse(status_code=502, content={"error": "No backend configured for this path", "path": path})

    upstream_url = upstream_base.rstrip("/") + path
    if request.url.query:
        upstream_url += f"?{request.url.query}"

    forward_headers = _forward_headers(headers_dict, risk, correlation_id)
    forward_headers["x-zombie-bootstrap"] = headers_dict.get("x-zombie-bootstrap", "")

    status_code = 502
    response_body = b""
    response_headers: Dict[str, str] = {}

    client = get_http_client()
    for attempt in range(settings.FORWARD_MAX_RETRIES + 1):
        try:
            upstream_resp = await client.request(method=method, url=upstream_url, headers=forward_headers, content=body)
            status_code = upstream_resp.status_code
            response_body = upstream_resp.content
            response_headers = dict(upstream_resp.headers)
            break
        except httpx.TimeoutException:
            log.warning("upstream_timeout", attempt=attempt, url=upstream_url)
            status_code = 504
            response_body = b'{"error":"upstream timeout"}'
        except httpx.ConnectError:
            log.warning("upstream_connect_error", attempt=attempt, url=upstream_url)
            status_code = 503
            response_body = b'{"error":"upstream unavailable"}'
        except Exception as exc:
            log.error("upstream_error", exc=str(exc), url=upstream_url)
            status_code = 502
            response_body = b'{"error":"gateway error"}'
            break

    await record_response_code(path, status_code)
    if status_code >= 400:
        await incr_counter("error_responses")
    else:
        await incr_counter("success_responses")

    await _persist_metadata(
        request_id=request_id,
        endpoint=path,
        method=method,
        source_ip=source_ip,
        headers_dict=headers_dict,
        payload_size=len(body),
        response_status=status_code,
        risk=risk,
    )

    event = {
        **event_base,
        "backend_url": upstream_base,
        "response_status": status_code,
        "warned": risk.warned,
        "blocked": False,
        "response_bytes": len(response_body),
        "latency_ms": round((time.monotonic() - start_ts) * 1000, 2),
    }
    await push_request_event(event)

    elapsed_ms = round((time.monotonic() - start_ts) * 1000, 2)
    clean_headers = {
        k: v for k, v in response_headers.items()
        if k.lower() not in {"transfer-encoding", "connection", "keep-alive", "content-encoding"}
    }
    clean_headers["x-zombie-score"] = str(risk.score)
    clean_headers["x-zombie-verdict"] = risk.verdict()
    if risk.warned:
        clean_headers["x-zombie-flags"] = ",".join(risk.flags)
    clean_headers["x-gateway-latency-ms"] = str(elapsed_ms)
    if correlation_id:
        clean_headers["x-correlation-id"] = correlation_id

    return Response(
        content=response_body,
        status_code=status_code,
        headers=clean_headers,
        media_type=response_headers.get("content-type", "application/json"),
    )
