"""
Central configuration for the Zombie API Gateway.
"""

from __future__ import annotations

import json
from typing import Dict, List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    GATEWAY_HOST: str = "0.0.0.0"
    GATEWAY_PORT: int = 8000
    GATEWAY_TITLE: str = "Zombie API Gateway"
    GATEWAY_VERSION: str = "1.0.0"
    LOG_LEVEL: str = "INFO"

    BACKEND_HOST: str = "localhost"
    BACKEND_PORT: int = 8001
    BACKEND_BASE_URL: str = "http://localhost:8001"

    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str = ""
    REDIS_STREAM_NAME: str = "zombie:requests"
    REDIS_CONSUMER_GROUP: str = "risk-engine"
    REDIS_MAXLEN: int = 10_000

    RISK_BLOCK_THRESHOLD: float = 0.75
    RISK_WARN_THRESHOLD: float = 0.40

    RATE_WINDOW_SECONDS: int = 60
    RATE_MAX_REQUESTS: int = 200

    BACKEND_ROUTES: str = json.dumps({
        "/": "http://localhost:8001",
        "/api": "http://localhost:8001",
        "/api/v0": "http://localhost:8001",
        "/api/v1": "http://localhost:8001",
        "/api/v2": "http://localhost:8001",
        "/api/admin": "http://localhost:8001",
        "/api/internal": "http://localhost:8001",
        "/api/beta": "http://localhost:8001",
        # Bait / Honeypot routes (TrapNet)
        "/.env": "http://localhost:8001",
        "/api/graphql": "http://localhost:8001",
        "/wp-admin": "http://localhost:8001",
        "/actuator": "http://localhost:8001",
        "/server-status": "http://localhost:8001",
    })

    DEPRECATED_PATHS: str = json.dumps([
        "/api/v0/", "/api/v1/", "/api/beta/", "/api/legacy/",
        "/old/", "/deprecated/", "/legacy/", "/api/users/export_all",
        "/api/admin/debug", "/api/v1/beta/",
        # Bait / Honeypot traps (TrapNet)
        "/.env", "/api/graphql", "/wp-admin/", "/actuator/",
        "/server-status", "/api/v1/admin/backup/", "/api/v1/config/secrets",
        "/api/v1/internal/ssh-keys", "/api/v1/debug/sql-console",
        "/api/v1/admin/impersonate", "/api/v1/payments/refund-override",
        "/api/v1/auth/tokens/refresh-all",
    ])
    DEBUG_PATHS: str = json.dumps([
        "/debug", "/api/debug", "/actuator", "/_debug", "/console",
        "/phpinfo", "/env", "/.env", "/config",
    ])
    INTERNAL_PATHS: str = json.dumps([
        "/api/internal", "/api/v1/internal", "/internal/", "/private/", "/_internal",
    ])
    DOCUMENTED_PREFIXES: str = json.dumps([
        "/api/health", "/api/docs", "/api/openapi.json",
        "/api/v0", "/api/v1", "/api/v2", "/api/admin", "/api/internal",
        "/api/beta",
        "/health", "/metrics", "/docs", "/openapi.json",
    ])
    AUTH_REQUIRED_PREFIXES: str = json.dumps([
        "/api/v2", "/api/admin", "/api/internal", "/api/v1/internal",
    ])

    ERROR_RATE_WINDOW: int = 300
    ERROR_RATE_THRESHOLD: float = 0.60

    HTTPX_TIMEOUT: float = 10.0
    FORWARD_MAX_RETRIES: int = 2

    SQLITE_DB_PATH: str = "data/zombie_gateway.sqlite3"
    SQLITE_RETENTION_DAYS: int = 14
    SQLITE_CLEANUP_ON_STARTUP: bool = True
    SQLITE_BUSY_TIMEOUT_MS: int = 3000
    SQLITE_MAX_REQUEST_EVENTS: int = 5000
    SQLITE_MAX_ALERTS: int = 2000

    # Semgrep Scanner / Brain AI Analysis
    GEMINI_API_KEY: str = ""
    SEMGREP_SCAN_TARGET: str = ""  # Empty = auto-detect app/ directory

    ENABLE_PROMETHEUS: bool = True
    DASHBOARD_KEY: str = "zombie-dashboard"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    def backend_map(self) -> Dict[str, str]:
        return json.loads(self.BACKEND_ROUTES)

    def deprecated_paths(self) -> List[str]:
        return json.loads(self.DEPRECATED_PATHS)

    def debug_paths(self) -> List[str]:
        return json.loads(self.DEBUG_PATHS)

    def internal_paths(self) -> List[str]:
        return json.loads(self.INTERNAL_PATHS)

    def documented_prefixes(self) -> List[str]:
        return json.loads(self.DOCUMENTED_PREFIXES)

    def auth_required_prefixes(self) -> List[str]:
        return json.loads(self.AUTH_REQUIRED_PREFIXES)


settings = Settings()
