"""Redis event layer for request events, counters, and intelligence caches."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

import redis.asyncio as aioredis

from core.config import settings

_pool: Optional[aioredis.Redis] = None
_consumer_groups_supported: Optional[bool] = None
_event_bus_mode: Optional[str] = None  # "stream" or "list"


async def get_redis() -> aioredis.Redis:
    global _pool
    if _pool is None:
        _pool = aioredis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            db=settings.REDIS_DB,
            password=settings.REDIS_PASSWORD or None,
            decode_responses=True,
            max_connections=50,
            socket_connect_timeout=5,
            socket_timeout=10,
            retry_on_timeout=True,
            health_check_interval=30,
        )
    return _pool


async def close_redis() -> None:
    global _pool
    if _pool:
        await _pool.aclose()
        _pool = None


def set_event_bus_mode(mode: str) -> None:
    global _event_bus_mode
    _event_bus_mode = mode


def event_bus_mode() -> str:
    return _event_bus_mode or "stream"


def consumer_groups_supported() -> Optional[bool]:
    return _consumer_groups_supported


async def probe_event_bus() -> str:
    r = await get_redis()
    global _event_bus_mode
    if _event_bus_mode:
        return _event_bus_mode

    probe_key = f"{settings.REDIS_STREAM_NAME}:probe"
    try:
        await r.xadd(probe_key, {"probe": "1"}, maxlen=1, approximate=True)
        await r.delete(probe_key)
        _event_bus_mode = "stream"
    except Exception:
        _event_bus_mode = "list"
    return _event_bus_mode


async def ensure_consumer_group() -> None:
    r = await get_redis()
    global _consumer_groups_supported
    try:
        await r.xgroup_create(
            settings.REDIS_STREAM_NAME,
            settings.REDIS_CONSUMER_GROUP,
            id="0",
            mkstream=True,
        )
        _consumer_groups_supported = True
    except aioredis.ResponseError as e:
        message = str(e).lower()
        if "busygroup" in message:
            _consumer_groups_supported = True
            return
        if "unknown command" in message or "xgroup" in message:
            _consumer_groups_supported = False
            set_event_bus_mode("list")
            return
        raise


async def push_request_event(event: Dict[str, Any]) -> str:
    r = await get_redis()
    flat = {k: v if isinstance(v, str) else json.dumps(v, default=str) for k, v in event.items()}
    if event_bus_mode() == "list":
        payload = json.dumps(flat, default=str)
        pipe = r.pipeline()
        pipe.rpush(settings.REDIS_STREAM_NAME, payload)
        pipe.ltrim(settings.REDIS_STREAM_NAME, -settings.REDIS_MAXLEN, -1)
        pipe.rpush(f"{settings.REDIS_STREAM_NAME}:queue", payload)
        msg_id, _, _ = await pipe.execute()
        return str(msg_id)

    msg_id = await r.xadd(
        settings.REDIS_STREAM_NAME,
        flat,
        maxlen=settings.REDIS_MAXLEN,
        approximate=True,
    )
    return msg_id


async def publish_alert_event(alert: Dict[str, Any]) -> str:
    """Publish an alert using Redis Streams when supported, otherwise a list fallback."""
    r = await get_redis()
    flat = {k: v if isinstance(v, str) else json.dumps(v, default=str) for k, v in alert.items()}

    if event_bus_mode() == "list":
        payload = json.dumps(flat, default=str)
        pipe = r.pipeline()
        pipe.rpush("zombie:alerts:list", payload)
        pipe.ltrim("zombie:alerts:list", -1000, -1)
        msg_id, _ = await pipe.execute()
        return str(msg_id)

    try:
        msg_id = await r.xadd("zombie:alerts", flat, maxlen=1000, approximate=True)
        return msg_id
    except Exception as exc:
        message = str(exc).lower()
        if "unknown command" in message or "xadd" in message:
            set_event_bus_mode("list")
            payload = json.dumps(flat, default=str)
            pipe = r.pipeline()
            pipe.rpush("zombie:alerts:list", payload)
            pipe.ltrim("zombie:alerts:list", -1000, -1)
            msg_id, _ = await pipe.execute()
            return str(msg_id)
        raise


async def increment_request_count(ip: str) -> int:
    r = await get_redis()
    key = f"ratelimit:{ip}"
    pipe = r.pipeline()
    pipe.incr(key)
    pipe.expire(key, settings.RATE_WINDOW_SECONDS)
    results = await pipe.execute()
    return results[0]


async def record_response_code(path: str, status: int) -> None:
    r = await get_redis()
    bucket = int(time.time() // settings.ERROR_RATE_WINDOW)
    base = f"errrate:{path}:{bucket}"
    pipe = r.pipeline()
    pipe.incr(f"{base}:total")
    if status >= 400:
        pipe.incr(f"{base}:errors")
    pipe.expire(f"{base}:total", settings.ERROR_RATE_WINDOW * 2)
    pipe.expire(f"{base}:errors", settings.ERROR_RATE_WINDOW * 2)
    await pipe.execute()


async def get_error_rate(path: str) -> float:
    r = await get_redis()
    bucket = int(time.time() // settings.ERROR_RATE_WINDOW)
    base = f"errrate:{path}:{bucket}"
    total_str = await r.get(f"{base}:total")
    errors_str = await r.get(f"{base}:errors")
    total = int(total_str) if total_str else 0
    errors = int(errors_str) if errors_str else 0
    if total == 0:
        return 0.0
    return errors / total


async def mark_zombie_endpoint(path: str, reason: str) -> None:
    r = await get_redis()
    data = {"path": path, "reason": reason, "detected_at": time.time()}
    await r.hset("zombie:endpoints", path, json.dumps(data))


async def get_all_zombies() -> List[Dict[str, Any]]:
    r = await get_redis()
    raw = await r.hgetall("zombie:endpoints")
    return [json.loads(v) for v in raw.values()]


async def get_stream_length() -> int:
    r = await get_redis()
    if event_bus_mode() == "list":
        return await r.llen(settings.REDIS_STREAM_NAME)
    return await r.xlen(settings.REDIS_STREAM_NAME)


async def get_recent_events(count: int = 50) -> List[Dict]:
    r = await get_redis()
    if event_bus_mode() == "list":
        entries = await r.lrange(settings.REDIS_STREAM_NAME, -count, -1)
        result: List[Dict] = []
        for idx, item in enumerate(reversed(entries)):
            try:
                decoded = json.loads(item)
            except (json.JSONDecodeError, TypeError):
                decoded = {"raw": item}
            decoded["_id"] = f"list-{idx}"
            result.append(decoded)
        return result

    entries = await r.xrevrange(settings.REDIS_STREAM_NAME, count=count)
    result: List[Dict] = []
    for msg_id, fields in entries:
        decoded = {"_id": msg_id}
        for k, v in fields.items():
            try:
                decoded[k] = json.loads(v)
            except (json.JSONDecodeError, TypeError):
                decoded[k] = v
        result.append(decoded)
    return result


async def incr_counter(name: str) -> int:
    r = await get_redis()
    return await r.incr(f"gw:counter:{name}")


async def get_all_counters() -> Dict[str, int]:
    r = await get_redis()
    keys = await r.keys("gw:counter:*")
    if not keys:
        return {}
    values = await r.mget(*keys)
    return {k.replace("gw:counter:", ""): int(v or 0) for k, v in zip(keys, values)}
