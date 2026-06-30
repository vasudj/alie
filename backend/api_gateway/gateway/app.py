"""Gateway application assembly: middleware, monitoring, proxy, startup/shutdown,
dynamic rule registry, and admin endpoints."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, Literal, Optional

import structlog
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core.config import settings
from core.logging import configure_logging
from db.db_helpers import init_sqlite_storage
from scanner.router import router as scanner_router
from scanner.websocket import ws_router as scanner_ws_router
from eventbus.redis_bus import (
    close_redis,
    consumer_groups_supported,
    ensure_consumer_group,
    event_bus_mode,
    get_redis,
    probe_event_bus,
)
from ops_monitoring.router import router as monitoring_router
from gateway.middleware import (
    CorrelationIDMiddleware,
    InlineEnforcementMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
    TelemetryScalerMiddleware,
)
from gateway.proxy import close_http_client, get_http_client, handle_request
from gateway.rule_registry import RULE_REGISTRY

configure_logging()
log = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Pydantic schemas for the admin rule API
# ---------------------------------------------------------------------------

class RulePayload(BaseModel):
    type: Literal["Blocklist", "Brownout", "Deprecation"]
    target: str                          # source IP (Blocklist) or URL path prefix (Brownout/Deprecation)
    meta: Optional[Dict[str, Any]] = None

class RuleResponse(BaseModel):
    rule_id: str
    type: str
    target: str
    meta: Optional[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("zombie_gateway_starting", port=settings.GATEWAY_PORT)
    r = await get_redis()
    await r.ping()
    await probe_event_bus()
    await ensure_consumer_group()
    await init_sqlite_storage()
    log.info(
        "redis_connected",
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        stream=settings.REDIS_STREAM_NAME,
    )

    get_http_client()
    log.info("http_client_ready")

    from scanner.semgrep_runner import REPORTS_DIR
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    log.info(
        "zombie_gateway_ready",
        title=settings.GATEWAY_TITLE,
        version=settings.GATEWAY_VERSION,
        block_threshold=settings.RISK_BLOCK_THRESHOLD,
        warn_threshold=settings.RISK_WARN_THRESHOLD,
        backends=list(settings.backend_map().keys()),
        backend_base_url=settings.BACKEND_BASE_URL,
        consumer_groups_supported=consumer_groups_supported(),
        event_bus_mode=event_bus_mode(),
    )
    yield
    log.info("zombie_gateway_shutting_down")
    await close_http_client()
    await close_redis()
    log.info("zombie_gateway_stopped")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.GATEWAY_TITLE,
        version=settings.GATEWAY_VERSION,
        description=(
            "Intelligent reverse proxy that detects zombie/shadow APIs, "
            "scores risk in real-time, and blocks dangerous requests."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Middleware is applied in reverse registration order (last registered = outermost).
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(TelemetryScalerMiddleware)       # extract metadata after response
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(InlineEnforcementMiddleware)     # enforce rules before proxying
    app.add_middleware(CorrelationIDMiddleware)

    app.include_router(monitoring_router)
    app.include_router(scanner_router)
    app.include_router(scanner_ws_router)

    # ------------------------------------------------------------------
    # Admin Rule Registry endpoints (private, not in OpenAPI schema)
    # ------------------------------------------------------------------

    @app.post("/admin/rules", response_model=RuleResponse, include_in_schema=False)
    async def create_rule(payload: RulePayload):
        """Push a new security rule into the live registry."""
        rule_id = f"rule-{uuid.uuid4().hex[:10]}"
        RULE_REGISTRY[rule_id] = {
            "type": payload.type,
            "target": payload.target,
            "meta": payload.meta or {},
        }
        log.info("rule_created", rule_id=rule_id, type=payload.type, target=payload.target)
        return RuleResponse(rule_id=rule_id, type=payload.type, target=payload.target, meta=payload.meta)

    @app.get("/admin/rules", include_in_schema=False)
    async def list_rules():
        """Return all active rules in the registry."""
        return {"total": len(RULE_REGISTRY), "rules": RULE_REGISTRY}

    @app.delete("/admin/rules/{rule_id}", include_in_schema=False)
    async def delete_rule(rule_id: str):
        """Remove a rule from the registry by its ID."""
        if rule_id not in RULE_REGISTRY:
            raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found.")
        removed = RULE_REGISTRY.pop(rule_id)
        log.info("rule_deleted", rule_id=rule_id, rule=removed)
        return {"deleted": rule_id, "rule": removed}

    # ------------------------------------------------------------------
    # Proxy catch-all (must be last)
    # ------------------------------------------------------------------

    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
        include_in_schema=False,
    )
    async def proxy_catchall(request: Request):
        return await handle_request(request)

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        log.error("unhandled_exception", path=request.url.path, exc=str(exc))
        return JSONResponse(
            status_code=500,
            content={"error": "Internal gateway error", "detail": str(exc)},
        )

    return app


app = create_app()
