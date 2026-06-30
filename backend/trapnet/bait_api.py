"""
Bait API Honeypot Endpoints — fake attack surfaces that lure hackers.

Every hit is logged as a trap event, published to the WebSocket stream,
and recorded for forensic analysis.  The responses look realistic enough
to keep an attacker engaged while the platform collects intelligence.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import random
import string
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, PlainTextResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["bait-honeypot"])

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rand(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _fake_token(length: int = 64) -> str:
    return hashlib.sha256(os.urandom(32)).hexdigest()[:length]


def _fake_ip() -> str:
    return f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


async def _simulate_processing():
    """Random delay to mimic real processing and keep attacker engaged."""
    await asyncio.sleep(random.uniform(0.1, 0.5))


async def _record_trap_hit(request: Request, bait_name: str, extra: Optional[Dict[str, Any]] = None):
    """Record the trap hit via the existing repository / event bus."""
    source_ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "")
    path = request.url.path
    method = request.method

    # ---------- Import repo lazily (it may not be ready at import time) ----------
    try:
        # Try gateway-side repo first (has insert_alert, increment_trap_hit, etc.)
        _api_gw_root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "api_gateway")
        if _api_gw_root not in sys.path:
            sys.path.insert(0, _api_gw_root)
        from db import repository as repo

        # Increment trap counter
        await repo.increment_trap_hit(path)

        # Insert alert
        await repo.insert_alert(
            severity="critical",
            title=f"BAIT TRAP HIT: {bait_name}",
            description=(
                f"Honeypot endpoint accessed — {method} {path}\n"
                f"Source IP: {source_ip}\n"
                f"User-Agent: {ua}\n"
                f"Bait: {bait_name}"
            ),
        )

        # Save forensic payload
        forensic_payload = {
            "bait_name": bait_name,
            "source_ip": source_ip,
            "user_agent": ua,
            "method": method,
            "path": path,
            "headers": dict(request.headers),
            "query_params": dict(request.query_params),
            "timestamp": _ts(),
        }
        if extra:
            forensic_payload["extra"] = extra

        await repo.insert_forensic(
            event_id=None,
            payload=json.dumps(forensic_payload, default=str),
            risk_score=0.95,
        )

        # Publish WebSocket event
        try:
            from api.websocket import broadcast
            await broadcast("new_trap_hit", {
                "bait": bait_name,
                "path": path,
                "method": method,
                "source_ip": source_ip,
                "user_agent": ua,
                "timestamp": _ts(),
            })
        except Exception:
            pass  # WebSocket relay might not be available

    except Exception as exc:
        logger.warning(f"Bait trap recording failed (non-critical): {exc}")

    logger.warning(
        f"BAIT TRAP HIT | {bait_name} | {method} {path} | "
        f"IP={source_ip} | UA={ua}"
    )


# ===========================================================================
# BAIT ENDPOINTS
# ===========================================================================

# ── 1. Database Dump ──────────────────────────────────────────────────────

@router.get("/api/v1/admin/backup/db-dump")
async def bait_db_dump(request: Request):
    """Fake database backup endpoint — looks like a full DB export."""
    await _simulate_processing()
    await _record_trap_hit(request, "db-dump")

    fake_users = [
        {
            "id": i,
            "email": f"user_{_rand(6)}@bankcore.com",
            "password_hash": f"$2b$12${_fake_token(53)}",
            "full_name": random.choice(["John Smith", "Jane Doe", "Robert Chen", "Maria Garcia", "Ahmed Hassan"]),
            "ssn_encrypted": _fake_token(32),
            "account_balance": round(random.uniform(500, 250000), 2),
            "role": random.choice(["user", "admin", "superadmin"]),
            "created_at": "2024-01-15T08:30:00Z",
        }
        for i in range(1, random.randint(8, 15))
    ]

    return JSONResponse(content={
        "status": "success",
        "export_format": "json",
        "database": "bankcore_production",
        "tables_exported": ["users", "accounts", "transactions", "sessions", "audit_logs"],
        "record_count": len(fake_users),
        "data": {"users": fake_users},
        "exported_at": _ts(),
        "warning": "CONFIDENTIAL — do not distribute",
    })


# ── 2. Secrets / Environment Config ──────────────────────────────────────

@router.get("/api/v1/config/secrets")
async def bait_config_secrets(request: Request):
    """Fake secrets / environment variables endpoint."""
    await _simulate_processing()
    await _record_trap_hit(request, "config-secrets")

    return JSONResponse(content={
        "environment": "production",
        "secrets": {
            "DATABASE_URL": f"postgresql://admin:SuperS3cret_{_rand(8)}@db-prod-01.internal:5432/bankcore",
            "REDIS_URL": "redis://:r3d1s_p@ss@cache-prod.internal:6379/0",
            "JWT_SECRET": _fake_token(48),
            "AWS_ACCESS_KEY_ID": f"AKIA{_rand(16).upper()}",
            "AWS_SECRET_ACCESS_KEY": _fake_token(40),
            "STRIPE_SECRET_KEY": f"sk_live_{_fake_token(32)}",
            "SENDGRID_API_KEY": f"SG.{_fake_token(22)}.{_fake_token(43)}",
            "ENCRYPTION_KEY": _fake_token(32),
            "INTERNAL_API_KEY": _fake_token(48),
            "SLACK_WEBHOOK": f"https://hooks.slack.com/services/T{_rand(10)}/B{_rand(10)}/{_fake_token(24)}",
        },
        "loaded_from": "/etc/bankcore/.env.production",
        "last_rotated": "2025-11-20T03:00:00Z",
    })


# ── 3. User Export (PII Dump) ────────────────────────────────────────────

@router.get("/api/v1/users/export_all")
async def bait_user_export(request: Request):
    """Fake PII user data export."""
    await _simulate_processing()
    await _record_trap_hit(request, "user-export-pii")

    users = []
    for i in range(1, random.randint(12, 25)):
        users.append({
            "user_id": i,
            "email": f"{_rand(6)}@{'gmail.com' if random.random() > 0.5 else 'outlook.com'}",
            "phone": f"+1-555-{random.randint(100,999)}-{random.randint(1000,9999)}",
            "ssn": f"{random.randint(100,999)}-{random.randint(10,99)}-{random.randint(1000,9999)}",
            "date_of_birth": f"19{random.randint(60,99)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
            "address": f"{random.randint(100,9999)} {random.choice(['Oak', 'Main', 'Elm', 'Cedar'])} St, {random.choice(['NY', 'CA', 'TX', 'FL'])}",
            "account_balance": round(random.uniform(100, 500000), 2),
        })

    return JSONResponse(content={
        "export_type": "full_user_dump",
        "total_users": len(users),
        "includes_pii": True,
        "data": users,
        "generated_at": _ts(),
    })


# ── 4. Token Refresh All ────────────────────────────────────────────────

@router.post("/api/v1/auth/tokens/refresh-all")
async def bait_token_refresh(request: Request):
    """Fake bulk token refresh — looks like mass session hijack potential."""
    await _simulate_processing()
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    await _record_trap_hit(request, "token-refresh-all", extra=body)

    tokens = [
        {
            "user_id": i,
            "access_token": f"eyJhbGciOiJIUzI1NiJ9.{_fake_token(36)}.{_fake_token(22)}",
            "refresh_token": _fake_token(48),
            "expires_in": 3600,
        }
        for i in range(1, random.randint(5, 12))
    ]

    return JSONResponse(content={
        "status": "refreshed",
        "tokens_refreshed": len(tokens),
        "tokens": tokens,
        "warning": "Admin-only operation",
    })


# ── 5. SSH Keys ──────────────────────────────────────────────────────────

@router.get("/api/v1/internal/ssh-keys")
async def bait_ssh_keys(request: Request):
    """Fake SSH key listing — irresistible to attackers."""
    await _simulate_processing()
    await _record_trap_hit(request, "ssh-keys")

    keys = [
        {
            "name": name,
            "fingerprint": f"SHA256:{_fake_token(43)}",
            "type": "ssh-rsa",
            "private_key_preview": f"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA{_fake_token(64)}\n...(truncated)...\n-----END RSA PRIVATE KEY-----",
            "host": host,
        }
        for name, host in [
            ("prod-deploy", "deploy@prod-01.internal"),
            ("db-backup", "backup@db-master.internal"),
            ("ci-runner", "ci@jenkins.internal"),
            ("monitoring", "grafana@monitor.internal"),
        ]
    ]

    return JSONResponse(content={
        "keys": keys,
        "total": len(keys),
        "vault_path": "/vault/secrets/ssh/production",
    })


# ── 6. Payment Refund Override ───────────────────────────────────────────

@router.post("/api/v1/payments/refund-override")
async def bait_refund_override(request: Request):
    """Fake payment refund override — financial bait."""
    await _simulate_processing()
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    await _record_trap_hit(request, "refund-override", extra=body)

    return JSONResponse(content={
        "status": "approved",
        "refund_id": f"RF-{_rand(10).upper()}",
        "amount": round(random.uniform(500, 50000), 2),
        "currency": "USD",
        "original_transaction": f"TXN-{_rand(12).upper()}",
        "approved_by": "system-override",
        "bypass_verification": True,
        "processed_at": _ts(),
    })


# ── 7. SQL Console ───────────────────────────────────────────────────────

@router.post("/api/v1/debug/sql-console")
async def bait_sql_console(request: Request):
    """Fake SQL console — every pentester's dream."""
    await _simulate_processing()
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    await _record_trap_hit(request, "sql-console", extra=body)

    query = body.get("query", "SELECT 1") if isinstance(body, dict) else "SELECT 1"

    return JSONResponse(content={
        "status": "executed",
        "query": query,
        "database": "bankcore_production",
        "rows_affected": random.randint(0, 150),
        "result": [
            {"id": 1, "table_name": "users", "row_count": 15423},
            {"id": 2, "table_name": "transactions", "row_count": 892341},
            {"id": 3, "table_name": "sessions", "row_count": 4521},
        ],
        "execution_time_ms": random.randint(5, 200),
        "warning": "Direct SQL access — audit logged",
    })


# ── 8. User Impersonation ───────────────────────────────────────────────

@router.post("/api/v1/admin/impersonate")
async def bait_impersonate(request: Request):
    """Fake admin impersonation — privilege escalation bait."""
    await _simulate_processing()
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    await _record_trap_hit(request, "admin-impersonate", extra=body)

    target = body.get("user_id", 1) if isinstance(body, dict) else 1

    return JSONResponse(content={
        "status": "impersonation_active",
        "original_admin": "admin@bankcore.com",
        "impersonating_user_id": target,
        "session_token": f"eyJhbGciOiJIUzI1NiJ9.{_fake_token(40)}.{_fake_token(22)}",
        "permissions": ["read", "write", "transfer", "admin"],
        "expires_in": 1800,
        "warning": "Impersonation session active — all actions logged",
    })


# ── 9. .env File ─────────────────────────────────────────────────────────

@router.get("/.env")
async def bait_dotenv(request: Request):
    """Fake .env file — classic recon target."""
    await _simulate_processing()
    await _record_trap_hit(request, "dotenv-file")

    env_content = f"""# ==========================================
# BANKCORE PRODUCTION CONFIG
# DO NOT COMMIT TO VERSION CONTROL
# ==========================================

NODE_ENV=production
PORT=8001
DATABASE_URL=postgresql://admin:P@ssw0rd_{_rand(8)}@db-prod.internal:5432/bankcore
REDIS_URL=redis://:r3d1s_{_rand(6)}@cache.internal:6379/0

JWT_SECRET={_fake_token(48)}
JWT_EXPIRY=3600
REFRESH_TOKEN_SECRET={_fake_token(48)}

AWS_ACCESS_KEY_ID=AKIA{_rand(16).upper()}
AWS_SECRET_ACCESS_KEY={_fake_token(40)}
AWS_REGION=us-east-1
S3_BUCKET=bankcore-prod-backups

STRIPE_SECRET_KEY=sk_live_{_fake_token(32)}
STRIPE_WEBHOOK_SECRET=whsec_{_fake_token(32)}

SMTP_HOST=smtp.sendgrid.net
SMTP_USER=apikey
SMTP_PASS=SG.{_fake_token(22)}.{_fake_token(43)}

ENCRYPTION_KEY={_fake_token(32)}
ADMIN_PASSWORD=admin_{_rand(12)}
"""

    return PlainTextResponse(content=env_content, media_type="text/plain")


# ── 10. GraphQL Introspection ────────────────────────────────────────────

@router.post("/api/graphql")
@router.get("/api/graphql")
async def bait_graphql(request: Request):
    """Fake GraphQL endpoint with introspection."""
    await _simulate_processing()
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    await _record_trap_hit(request, "graphql-introspection", extra=body)

    return JSONResponse(content={
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "types": [
                    {"name": "User", "fields": ["id", "email", "password_hash", "ssn", "balance", "role"]},
                    {"name": "Transaction", "fields": ["id", "from_account", "to_account", "amount", "status"]},
                    {"name": "Session", "fields": ["id", "user_id", "token", "ip_address", "expires_at"]},
                    {"name": "AdminConfig", "fields": ["key", "value", "secret", "last_modified"]},
                ],
                "directives": [{"name": "auth", "description": "Requires authentication (BYPASS: send x-admin-override header)"}],
            }
        }
    })


# ── 11. WordPress Admin Bait ─────────────────────────────────────────────

@router.api_route("/wp-admin/admin-ajax.php", methods=["GET", "POST"])
async def bait_wp_admin(request: Request):
    """WordPress admin-ajax bait — catches bot scanners."""
    await _simulate_processing()
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    await _record_trap_hit(request, "wordpress-admin", extra=body)

    return JSONResponse(content={
        "success": True,
        "data": {
            "wp_version": "6.4.2",
            "plugins": [
                {"name": "wp-file-manager", "version": "7.1", "active": True},
                {"name": "duplicate-page", "version": "4.5", "active": True},
            ],
            "theme": "developer-portal",
            "admin_email": f"admin@{_rand(6)}.com",
            "upload_dir": "/var/www/html/wp-content/uploads/",
            "debug_mode": True,
        },
    })


# ── 12. Spring Boot Actuator Bait ────────────────────────────────────────

@router.get("/actuator/env")
async def bait_actuator_env(request: Request):
    """Spring Boot actuator bait — catches Java-focused scanners."""
    await _simulate_processing()
    await _record_trap_hit(request, "actuator-env")

    return JSONResponse(content={
        "activeProfiles": ["production"],
        "propertySources": [
            {
                "name": "systemEnvironment",
                "properties": {
                    "SPRING_DATASOURCE_URL": {"value": f"jdbc:postgresql://db-prod:5432/bankcore"},
                    "SPRING_DATASOURCE_PASSWORD": {"value": f"dbpass_{_rand(12)}"},
                    "SPRING_REDIS_HOST": {"value": "cache-prod.internal"},
                    "JWT_SECRET": {"value": _fake_token(48)},
                    "AWS_ACCESS_KEY_ID": {"value": f"AKIA{_rand(16).upper()}"},
                    "AWS_SECRET_ACCESS_KEY": {"value": _fake_token(40)},
                    "ENCRYPTION_KEY": {"value": _fake_token(32)},
                },
            },
        ],
    })


# ── 13. Server Status (bonus) ───────────────────────────────────────────

@router.get("/server-status")
async def bait_server_status(request: Request):
    """Apache-style server-status bait."""
    await _simulate_processing()
    await _record_trap_hit(request, "server-status")

    return PlainTextResponse(content=f"""Apache Server Status for bankcore-prod-01.internal (via 10.0.1.50)

Server Version: Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2
Server MPM: event
Server Built: 2024-01-10T14:22:00

Current Time: {_ts()}
Restart Time: 2025-12-01T03:00:00Z
Server uptime: 207 days 14 hours 30 minutes

Total accesses: 8942381 - Total Traffic: 42.3 GB
CPU Usage: u12.5 s8.2 cu0 cs0 - .00142% CPU load
14.2 requests/sec - 234.1 kB/second - 16.5 kB/request

Scoreboard: WWWW....KK...WW....KKKKK.......WW....
  W = Sending reply, K = Keepalive, . = Open slot

  Srv  PID   Acc    M CPU   SS  Req  Conn  Child  Slot    Client            VHost              Request
  0-0  14523 0/42/1523 W 0.12 0 0 0.0  2.14  234.12  10.0.1.100     bankcore.com      GET /api/v2/accounts/balance
  1-0  14524 0/38/1421 W 0.09 1 1 0.0  1.89  198.34  {_fake_ip()}  admin.bankcore.com POST /api/admin/login
  2-0  14525 0/55/2103 K 0.15 5 0 0.0  3.21  401.22  {_fake_ip()}  bankcore.com      GET /api/v1/quick-pay
""", media_type="text/plain")
