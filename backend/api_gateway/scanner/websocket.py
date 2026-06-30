"""
WebSocket stub for real-time scanner updates.

This module provides a WebSocket endpoint that the frontend can connect to
for receiving real-time scan status updates. Currently a stub that will be
fully wired when the Brain's socket layer is added.

Protocol (future):
    1. Frontend connects to ws://gateway:8080/ws/scanner
    2. Frontend sends: {"action": "subscribe", "scan_id": "<id>"}
    3. Server sends status updates:
       - {"type": "scan_status", "scan_id": "...", "status": "running"}
       - {"type": "scan_progress", "scan_id": "...", "progress": 45}
       - {"type": "scan_completed", "scan_id": "...", "findings_count": 12}
       - {"type": "analysis_ready", "scan_id": "...", "severity": "HIGH"}
"""

from __future__ import annotations

import json
from typing import Dict, Set

import structlog
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

log = structlog.get_logger(__name__)

ws_router = APIRouter()

# Active WebSocket connections, keyed by scan_id they're subscribed to
_connections: Dict[str, Set[WebSocket]] = {}


async def broadcast_scan_update(scan_id: str, data: Dict) -> None:
    """
    Broadcast a scan update to all WebSocket clients subscribed to this scan_id.

    Call this from the scanner router when scan status changes.
    This is a no-op if no clients are connected (graceful degradation).
    """
    subscribers = _connections.get(scan_id, set())
    if not subscribers:
        return

    message = json.dumps({"scan_id": scan_id, **data})
    dead: Set[WebSocket] = set()

    for ws in subscribers:
        try:
            await ws.send_text(message)
        except Exception:
            dead.add(ws)

    # Clean up dead connections
    for ws in dead:
        subscribers.discard(ws)
    if not subscribers:
        _connections.pop(scan_id, None)


@ws_router.websocket("/ws/scanner")
async def scanner_websocket(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for real-time scanner updates.

    Stub implementation — accepts connections and echoes subscription confirmations.
    Will be fully wired with the Brain socket layer in the future.
    """
    await websocket.accept()
    subscribed_scans: Set[str] = set()
    log.info("ws_scanner_connected", client=str(websocket.client))

    try:
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to scanner WebSocket. Send {\"action\": \"subscribe\", \"scan_id\": \"<id>\"} to receive updates.",
        })

        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "message": "Invalid JSON"})
                continue

            action = msg.get("action", "")
            scan_id = msg.get("scan_id", "")

            if action == "subscribe" and scan_id:
                # Register this connection for scan updates
                if scan_id not in _connections:
                    _connections[scan_id] = set()
                _connections[scan_id].add(websocket)
                subscribed_scans.add(scan_id)
                await websocket.send_json({
                    "type": "subscribed",
                    "scan_id": scan_id,
                    "message": f"Subscribed to updates for scan {scan_id}",
                })
                log.info("ws_scanner_subscribed", scan_id=scan_id)

            elif action == "unsubscribe" and scan_id:
                if scan_id in _connections:
                    _connections[scan_id].discard(websocket)
                subscribed_scans.discard(scan_id)
                await websocket.send_json({
                    "type": "unsubscribed",
                    "scan_id": scan_id,
                })

            elif action == "ping":
                await websocket.send_json({"type": "pong"})

            else:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Unknown action: {action}. Supported: subscribe, unsubscribe, ping",
                })

    except WebSocketDisconnect:
        log.info("ws_scanner_disconnected", client=str(websocket.client))
    except Exception as exc:
        log.error("ws_scanner_error", error=str(exc))
    finally:
        # Cleanup subscriptions
        for scan_id in subscribed_scans:
            if scan_id in _connections:
                _connections[scan_id].discard(websocket)
                if not _connections[scan_id]:
                    del _connections[scan_id]
