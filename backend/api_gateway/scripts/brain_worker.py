"""Compatibility wrapper for the refactored brain worker (moved to scripts/)."""

from pathlib import Path
import sys

# Ensure package imports work when running this script from the scripts/ directory
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from brain.worker import run_brain_engine


if __name__ == "__main__":
    import asyncio
    import structlog

    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.add_log_level,
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
    )
    asyncio.run(run_brain_engine())
