"""
ALIE — API Gateway Entry Point
================================
Run:
    cd alie/backend/api_gateway
    python main.py

The gateway listens on 0.0.0.0:8000 and reverse-proxies all traffic
to the Bank Backend at http://localhost:8001.

Override any default via environment variable:
    GATEWAY_PORT=9000 python main.py
    BACKEND_BASE_URL=http://localhost:3001 python main.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# ── Make sure the api_gateway package root is on sys.path so that
#    `from core.config import settings` etc. resolve correctly when
#    this file is executed directly (not as part of a package).
ROOT = Path(__file__).resolve().parent          # .../api_gateway/
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import uvicorn
from core.config import settings
from gateway.app import app                     # noqa: E402  (import after path fix)


if __name__ == "__main__":
    print(
        f"\n  ALIE API Gateway\n"
        f"  ─────────────────────────────────────────\n"
        f"  Listening  : http://0.0.0.0:{settings.GATEWAY_PORT}\n"
        f"  Backend    : {settings.BACKEND_BASE_URL}\n"
        f"  Log level  : {settings.LOG_LEVEL}\n"
        f"  Docs       : http://localhost:{settings.GATEWAY_PORT}/docs\n"
        f"  Admin rules: POST http://localhost:{settings.GATEWAY_PORT}/admin/rules\n"
        f"  ─────────────────────────────────────────\n"
    )

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=settings.GATEWAY_PORT,         # default 8000, override via GATEWAY_PORT=
        reload=False,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=True,
        workers=1,
    )
