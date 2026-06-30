"""Gateway middleware stack: correlation IDs, request logging, and headers."""

from __future__ import annotations

import time
import uuid
from typing import Callable

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

log = structlog.get_logger(__name__)


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
