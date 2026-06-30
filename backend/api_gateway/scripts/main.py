"""Compatibility entrypoint for the refactored gateway application (moved to scripts/)."""

from __future__ import annotations

from pathlib import Path
import sys
import uvicorn

# Ensure package imports work when running this script from the scripts/ directory
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.config import settings
from gateway.app import app, create_app


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=settings.GATEWAY_HOST,
        port=settings.GATEWAY_PORT,
        reload=False,
        log_level=settings.LOG_LEVEL.lower(),
        access_log=False,
        workers=1,
    )
