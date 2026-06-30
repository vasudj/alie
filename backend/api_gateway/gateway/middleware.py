"""Gateway middleware stack: correlation IDs, request logging, security headers,
telemetry extraction (Log Scaler-Downer), and inline rule enforcement."""

from __future__ import annotations

import asyncio
import json
import random
import time
import uuid
from pathlib import Path
from typing import Callable

import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from gateway.rule_registry import RULE_REGISTRY

log = structlog.get_logger(__name__)

# Telemetry log — one JSON object per line, no payload bodies.
_AUDIT_LOG = Path("scaled_down_audit.log")
_audit_lock = asyncio.Lock()


async def _append_telemetry(record: dict) -> None:
    line = json.dumps(record, default=str) + "\n"
    async with _audit_lock:
        await asyncio.to_thread(_AUDIT_LOG.open("a", encoding="utf-8").write, line)


# ---------------------------------------------------------------------------
# Correlation ID
# ---------------------------------------------------------------------------

class CorrelationIDMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        correlation_id = (
            request.headers.get("x-correlation-id")
            or request.headers.get("x-request-id")
            or f"zgw-{uuid.uuid4().hex[:12]}"
        )
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["x-correlation-id"] = correlation_id
        return response


# ---------------------------------------------------------------------------
# Inline Rule Enforcement  (runs BEFORE proxying)
# ---------------------------------------------------------------------------

class InlineEnforcementMiddleware(BaseHTTPMiddleware):
    """Check the live RULE_REGISTRY and enforce Blocklist / Brownout / Deprecation rules."""

    BROWNOUT_DROP_RATE = 0.05   # 5 % of requests dropped during brownout

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        source_ip = request.client.host if request.client else "unknown"
        path = request.url.path
        correlation_id = getattr(request.state, "correlation_id", "")

        blocklisted = False
        brownout_paths: list[str] = []
        deprecation_paths: list[str] = []

        for rule in RULE_REGISTRY.values():
            rule_type = rule.get("type", "")
            target = rule.get("target", "")

            if rule_type == "Blocklist" and target == source_ip:
                blocklisted = True

            elif rule_type == "Brownout" and path.startswith(target):
                brownout_paths.append(target)

            elif rule_type == "Deprecation" and path.startswith(target):
                deprecation_paths.append(target)

        # --- Blocklist: hard 403 ---
        if blocklisted:
            log.warning("inline_enforcement_blocked", ip=source_ip, path=path)
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Forbidden",
                    "detail": "Your IP has been blocked by the security policy.",
                    "correlation_id": correlation_id,
                },
                headers={"X-Enforcement": "Blocklist", "X-Correlation-ID": correlation_id},
            )

        # --- Brownout: randomly drop 5 % ---
        if brownout_paths and random.random() < self.BROWNOUT_DROP_RATE:
            log.warning("inline_enforcement_brownout_drop", path=path)
            return JSONResponse(
                status_code=503,
                content={
                    "error": "Service Unavailable",
                    "detail": "Endpoint is under brownout — try again later.",
                    "correlation_id": correlation_id,
                },
                headers={"X-Enforcement": "Brownout", "X-Correlation-ID": correlation_id, "Retry-After": "5"},
            )

        response = await call_next(request)

        # --- Deprecation: inject warning headers on the way back out ---
        if deprecation_paths:
            response.headers["Deprecation"] = "true"
            response.headers["Warning"] = '299 - "This endpoint is deprecated and will be removed."'
            response.headers["X-Enforcement"] = "Deprecation"

        return response


# ---------------------------------------------------------------------------
# Log Scaler-Downer  (telemetry extractor — no payload bodies)
# ---------------------------------------------------------------------------

class TelemetryScalerMiddleware(BaseHTTPMiddleware):
    """Extract request/response metadata and append as a JSON line to scaled_down_audit.log."""

    SKIP_PATHS = {"/health", "/metrics", "/favicon.ico"}

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in self.SKIP_PATHS:
            return await call_next(request)

        start = time.monotonic()
        # Read body length without consuming it (body is already buffered by ASGI).
        body = await request.body()
        payload_size = len(body)

        response = await call_next(request)

        latency_ms = round((time.monotonic() - start) * 1000, 2)
        source_ip = request.client.host if request.client else "unknown"

        # Attempt to read response size from Content-Length header (zero-cost).
        # The proxy sets this from the upstream response; 0 if absent or chunked.
        try:
            response_bytes = int(response.headers.get("content-length", 0))
        except (ValueError, TypeError):
            response_bytes = 0

        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "method": request.method,
            "path": request.url.path,
            "source_ip": source_ip,
            "status_code": response.status_code,
            "latency_ms": latency_ms,
            "request_bytes": payload_size,
            "response_bytes": response_bytes,
        }

        # Fire-and-forget — never block the response path.
        asyncio.ensure_future(_append_telemetry(record))

        return response


# ---------------------------------------------------------------------------
# Request Logging
# ---------------------------------------------------------------------------

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    SKIP_PATHS = {"/health", "/metrics", "/favicon.ico"}

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in self.SKIP_PATHS:
            return await call_next(request)

        start = time.monotonic()
        correlation_id = getattr(request.state, "correlation_id", "-")
        logger = log.bind(
            correlation_id=correlation_id,
            method=request.method,
            path=request.url.path,
            ip=request.client.host if request.client else "unknown",
            ua=request.headers.get("user-agent", "")[:80],
        )
        logger.info("request_received")

        try:
            response = await call_next(request)
        except Exception as exc:
            logger.exception("unhandled_exception", exc=str(exc))
            raise

        elapsed_ms = round((time.monotonic() - start) * 1000, 2)
        verdict = response.headers.get("x-zombie-verdict", "ALLOWED")
        if not verdict and response.status_code < 400:
            verdict = "ALLOWED"
        logger.info(
            "request_completed",
            status=response.status_code,
            ms=elapsed_ms,
            verdict=verdict,
            score=response.headers.get("x-zombie-score", ""),
            correlation_id=correlation_id,
        )
        return response


# ---------------------------------------------------------------------------
# Security Headers
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cache-Control": "no-store",
        "Server": "ZombieGateway/1.0",
    }

    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        for header, value in self.SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response
