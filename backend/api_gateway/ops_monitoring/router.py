"""Monitoring layer: metrics, dashboards, health, and read-only inspection endpoints."""

from __future__ import annotations

import json
import time
from typing import Optional
from urllib.parse import unquote

from fastapi import APIRouter, Header, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import asyncio

from core.config import settings
from detection.scorer import score_request
from eventbus.redis_bus import get_all_counters, get_all_zombies, get_recent_events, get_redis, get_stream_length

router = APIRouter(tags=["monitoring"])


@router.get("/health")
async def health():
    return {"status": "ok", "gateway": settings.GATEWAY_TITLE, "version": settings.GATEWAY_VERSION, "ts": time.time()}


@router.get("/status")
async def status():
    r = await get_redis()
    redis_ok = False
    redis_info = {}
    try:
        redis_ok = await r.ping()
        info = await r.info("server")
        redis_info = {
            "version": info.get("redis_version"),
            "uptime_seconds": info.get("uptime_in_seconds"),
            "connected_clients": info.get("connected_clients"),
        }
    except Exception as e:
        redis_info = {"error": str(e)}

    stream_len = 0
    try:
        stream_len = await get_stream_length()
    except Exception:
        pass

    counters = await get_all_counters()
    return {
        "gateway": {"status": "running", "title": settings.GATEWAY_TITLE, "version": settings.GATEWAY_VERSION, "ts": time.time()},
        "redis": {"ok": redis_ok, **redis_info},
        "stream": {"name": settings.REDIS_STREAM_NAME, "length": stream_len},
        "counters": counters,
        "thresholds": {"block": settings.RISK_BLOCK_THRESHOLD, "warn": settings.RISK_WARN_THRESHOLD},
        "backend": {"base_url": settings.BACKEND_BASE_URL, "routes": settings.backend_map()},
        "backends": list(settings.backend_map().keys()),
    }


@router.get("/metrics")
async def prometheus_metrics():
    counters = await get_all_counters()
    zombies = await get_all_zombies()
    stream_len = await get_stream_length()
    lines = [
        "# HELP zombie_gateway_requests_total Total requests through the gateway",
        "# TYPE zombie_gateway_requests_total counter",
        f'zombie_gateway_requests_total {counters.get("total_requests", 0)}',
        "",
        "# HELP zombie_gateway_blocked_total Requests blocked by risk engine",
        "# TYPE zombie_gateway_blocked_total counter",
        f'zombie_gateway_blocked_total {counters.get("blocked_requests", 0)}',
        "",
        "# HELP zombie_gateway_errors_total Error responses from upstreams",
        "# TYPE zombie_gateway_errors_total counter",
        f'zombie_gateway_errors_total {counters.get("error_responses", 0)}',
        "",
        "# HELP zombie_endpoints_detected Number of unique zombie endpoints",
        "# TYPE zombie_endpoints_detected gauge",
        f"zombie_endpoints_detected {len(zombies)}",
        "",
        "# HELP zombie_stream_length Redis Stream backlog length",
        "# TYPE zombie_stream_length gauge",
        f"zombie_stream_length {stream_len}",
        "",
    ]
    return Response(content="\n".join(lines), media_type="text/plain")


@router.get("/zombies")
async def list_zombies():
    zombies = await get_all_zombies()
    return {"count": len(zombies), "zombies": zombies}


@router.delete("/zombies/{encoded_path:path}")
async def clear_zombie(encoded_path: str, x_dashboard_key: Optional[str] = Header(None)):
    if x_dashboard_key != settings.DASHBOARD_KEY:
        raise HTTPException(status_code=401, detail="Invalid dashboard key")
    path = "/" + unquote(encoded_path)
    r = await get_redis()
    deleted = await r.hdel("zombie:endpoints", path)
    if deleted == 0:
        raise HTTPException(status_code=404, detail="Zombie path not found")
    return {"deleted": path}


@router.get("/events")
async def recent_events(limit: int = Query(default=50, ge=1, le=500)):
    events = await get_recent_events(count=limit)
    return {"count": len(events), "events": events}


@router.websocket("/ws/telemetry/")
async def telemetry_websocket(websocket: WebSocket):
    await websocket.accept()
    seen_hashes: set = set()
    
    def _evt_hash(evt: dict) -> str:
        """Create a unique hash for an event to avoid duplicates."""
        return f"{evt.get('source_ip','')}-{evt.get('method','')}-{evt.get('path','')}-{evt.get('timestamp','')}"
    
    def _format_event(evt: dict) -> dict:
        """Format a raw Redis event into a frontend-compatible WsTelemetryFrame."""
        flags = evt.get("flags", [])
        verdict = evt.get("verdict", "ALLOW")
        is_threat = verdict in ("BLOCK", "BLOCKED", "BANNED")
        threat_sig = None
        if is_threat and flags:
            threat_sig = flags[0] if isinstance(flags, list) else str(flags)
        return {
            "event": {
                "id": evt.get("_id", str(time.time())),
                "created_at": evt.get("timestamp", time.time()),
                "threat_signature": threat_sig,
                "method": evt.get("method", "GET"),
                "url": evt.get("path", "/"),
                "ip": evt.get("source_ip", "0.0.0.0"),
                "action": verdict
            }
        }
    
    # Send initial batch of recent events
    recent = await get_recent_events(count=20)
    for evt in reversed(recent):
        h = _evt_hash(evt)
        seen_hashes.add(h)
        await websocket.send_json(_format_event(evt))
    
    # Keep seen_hashes bounded
    if len(seen_hashes) > 500:
        seen_hashes = set(list(seen_hashes)[-200:])
    
    try:
        while True:
            await asyncio.sleep(0.3)
            events = await get_recent_events(count=20)
            for evt in reversed(events):
                h = _evt_hash(evt)
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    await websocket.send_json(_format_event(evt))
            # Keep bounded
            if len(seen_hashes) > 500:
                seen_hashes = set(list(seen_hashes)[-200:])
    except WebSocketDisconnect:
        pass


@router.get("/counters")
async def get_counters():
    counters = await get_all_counters()
    total = counters.get("total_requests", 1) or 1
    blocked = counters.get("blocked_requests", 0)
    return {**counters, "block_rate_pct": round(blocked / total * 100, 2)}


@router.get("/brain")
async def brain_summary():
    r = await get_redis()
    summary = await r.get("brain:summary")
    if not summary:
        return {"status": "warming_up", "summary": None}
    try:
        return {"status": "ok", "summary": json.loads(summary)}
    except Exception:
        return {"status": "ok", "summary": summary}


@router.get("/risk/score")
async def ad_hoc_score(path: str = Query(..., description="Path to evaluate"), method: str = Query(default="GET"), ip: str = Query(default="127.0.0.1"), authorization: Optional[str] = Query(default=None)):
    headers = {}
    if authorization:
        headers["authorization"] = authorization
    result = await score_request(path=path, method=method, source_ip=ip, headers=headers, query_params={})
    return {
        "path": path,
        "method": method,
        "score": result.score,
        "verdict": result.verdict(),
        "flags": result.flags,
        "details": result.details,
        "thresholds": {"block": settings.RISK_BLOCK_THRESHOLD, "warn": settings.RISK_WARN_THRESHOLD},
    }


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    counters = await get_all_counters()
    zombies = await get_all_zombies()
    events = await get_recent_events(count=20)
    stream_len = await get_stream_length()
    total = counters.get("total_requests", 0)
    blocked = counters.get("blocked_requests", 0)
    errors = counters.get("error_responses", 0)
    block_rate = round(blocked / max(total, 1) * 100, 1)
    zombie_rows = "".join(f"<tr><td>{z['path']}</td><td class='tag'>{z['reason']}</td><td>{round(z['detected_at'])}</td></tr>" for z in zombies)

    def _event_row(e: dict) -> str:
        verdict = e.get("verdict", "")
        return (
            f"<tr>"
            f"<td>{e.get('path','')}</td>"
            f"<td>{e.get('method','')}</td>"
            f"<td>{e.get('source_ip','')}</td>"
            f"<td class='score'>{float(e.get('risk_score', 0)):.2f}</td>"
            f"<td class='verdict {verdict.lower()}'>{verdict}</td>"
            f"</tr>"
        )

    event_rows = "".join(_event_row(e) for e in events)
    html = f"""
<html><head><title>Zombie API Gateway</title></head><body>
<h1>Zombie API Gateway</h1>
<p>Total: {total} | Blocked: {blocked} | Errors: {errors} | Block rate: {block_rate}% | Stream: {stream_len}</p>
<table>{zombie_rows}</table>
<table>{event_rows}</table>
</body></html>
"""
    return HTMLResponse(html)
