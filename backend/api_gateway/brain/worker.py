"""Brain Engine worker loop, isolated from gateway blocking decisions."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import structlog

from core.config import settings
from eventbus.redis_bus import (
    consumer_groups_supported,
    ensure_consumer_group,
    event_bus_mode,
    get_redis,
    probe_event_bus,
    close_redis,
)
from brain.engine import BrainEngine

log = structlog.get_logger(__name__)

CONSUMER_NAME = "brain-engine-1"
BATCH_SIZE = 10
POLL_BLOCK_MS = 2000


async def run_brain_engine() -> None:
    print("Brain Engine starting...")
    log.info("brain_engine_starting", stream=settings.REDIS_STREAM_NAME, group=settings.REDIS_CONSUMER_GROUP, consumer=CONSUMER_NAME)

    r = None
    for attempt in range(1, 6):
        try:
            r = await get_redis()
            await asyncio.wait_for(r.ping(), timeout=3)
            break
        except Exception as exc:
            log.error("redis_connect_retry", attempt=attempt, exc=str(exc))
            print(f"Redis not ready (attempt {attempt}/5): {exc}")
            await asyncio.sleep(2)

    if r is None:
        raise RuntimeError("Redis is unavailable after retries")

    await probe_event_bus()
    await ensure_consumer_group()
    engine = BrainEngine()
    use_groups = consumer_groups_supported() is not False
    use_list_queue = event_bus_mode() == "list"

    print(f"Brain Engine connected. event_bus_mode={event_bus_mode()} use_groups={use_groups}")
    log.info("brain_engine_ready", event_bus_mode=event_bus_mode(), use_groups=use_groups, use_list_queue=use_list_queue)

    summary_tick = 0
    while True:
        messages = []
        try:
            if use_list_queue:
                item = await r.brpop(f"{settings.REDIS_STREAM_NAME}:queue", timeout=POLL_BLOCK_MS // 1000)
                if not item:
                    continue
                _, payload = item
                try:
                    event = json.loads(payload)
                except (json.JSONDecodeError, TypeError):
                    event = {"raw": payload}
                await engine.process_event(r, event)
            elif use_groups:
                messages = await r.xreadgroup(
                    groupname=settings.REDIS_CONSUMER_GROUP,
                    consumername=CONSUMER_NAME,
                    streams={settings.REDIS_STREAM_NAME: ">"},
                    count=BATCH_SIZE,
                    block=POLL_BLOCK_MS,
                )
                if not messages:
                    pending = await r.xreadgroup(
                        groupname=settings.REDIS_CONSUMER_GROUP,
                        consumername=CONSUMER_NAME,
                        streams={settings.REDIS_STREAM_NAME: "0"},
                        count=BATCH_SIZE,
                    )
                    messages = pending or []
            else:
                messages = []

            for _, entries in (messages or []):
                ack_ids = []
                for msg_id, fields in entries:
                    event: dict = {}
                    for k, v in fields.items():
                        try:
                            event[k] = json.loads(v)
                        except (json.JSONDecodeError, TypeError):
                            event[k] = v
                    await engine.process_event(r, event)
                    ack_ids.append(msg_id)

                if use_groups and ack_ids:
                    await r.xack(settings.REDIS_STREAM_NAME, settings.REDIS_CONSUMER_GROUP, *ack_ids)

            summary_tick += 1
            if summary_tick % 50 == 0:
                await engine.persist_summary(r)

        except asyncio.CancelledError:
            log.info("brain_engine_cancelled")
            break
        except Exception as exc:
            # Ensure messages is reset so next loop doesn't reference an undefined var
            log.error("brain_engine_error", exc=str(exc))
            messages = []
            await asyncio.sleep(2)
            continue

    try:
        await engine.persist_summary(r)
    except Exception:
        pass
    try:
        await close_redis()
    except Exception:
        pass
    log.info("brain_engine_stopped", processed=engine.events_processed, alerts=engine.alerts_emitted)


if __name__ == "__main__":
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
