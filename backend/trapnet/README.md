# TrapNet — Honeypot Integration Guide

> **Feature owner:** TrapNet module  
> **Status:** Standalone & working — ready for integration into the main ALIE product  
> **Last updated:** 2026-06-26

---

## What is TrapNet?

TrapNet is the **honeypot / bait API** layer for the ALIE RTLS Security Platform. It deploys **13 fake attack-surface endpoints** that look like real vulnerabilities (database dumps, SSH keys, `.env` files, admin panels, etc.). When an attacker hits any of these, the system:

1. Returns realistic-looking fake data (to keep the attacker engaged)
2. Logs the hit as a **critical alert** with full forensic capture
3. Publishes a `new_trap_hit` event to the WebSocket stream (for the live terminal UI)
4. Records everything: IP, User-Agent, headers, query params, request body

It also includes a **standalone Live Terminal UI** (`terminal.html`) that connects to the Gateway WebSocket and displays all events in real-time with color-coded categories and filters.

---

## Folder Structure

```
trapnet/
├── __init__.py           # Package init
├── bait_api.py           # FastAPI router — 13 honeypot endpoints
├── terminal.html         # Standalone live event terminal UI (HTML/CSS/JS)
└── README.md             # This file (integration guide)
```

---

## Honeypot Endpoints (bait_api.py)

The router exposes 13 bait endpoints. **All of them are fake** — they return randomly generated convincing data and silently record every hit.

| #  | Method     | Path                                 | Disguise                              |
|----|------------|--------------------------------------|---------------------------------------|
| 1  | `GET`      | `/api/v1/admin/backup/db-dump`       | Fake database export with user records |
| 2  | `GET`      | `/api/v1/config/secrets`             | Fake env vars (AWS keys, JWT, DB URLs) |
| 3  | `GET`      | `/api/v1/users/export_all`           | Fake PII dump (SSNs, phones, addresses)|
| 4  | `POST`     | `/api/v1/auth/tokens/refresh-all`    | Fake bulk JWT token refresh            |
| 5  | `GET`      | `/api/v1/internal/ssh-keys`          | Fake SSH private keys for prod servers |
| 6  | `POST`     | `/api/v1/payments/refund-override`   | Fake payment refund bypass             |
| 7  | `POST`     | `/api/v1/debug/sql-console`          | Fake SQL execution console             |
| 8  | `POST`     | `/api/v1/admin/impersonate`          | Fake admin user impersonation          |
| 9  | `GET`      | `/.env`                              | Fake .env file with credentials        |
| 10 | `GET/POST` | `/api/graphql`                       | Fake GraphQL introspection schema      |
| 11 | `GET/POST` | `/wp-admin/admin-ajax.php`           | WordPress admin bait (catches bots)    |
| 12 | `GET`      | `/actuator/env`                      | Spring Boot actuator bait              |
| 13 | `GET`      | `/server-status`                     | Apache server-status page bait         |

---

## How to Integrate

### Step 1 — Register the Router in `app/main.py`

Add the import at the top with the other router imports:

```python
from trapnet.bait_api import router as bait_router
```

Then register it alongside the other routers:

```python
app.include_router(bait_router)
```

> **Note:** The router has no prefix — each endpoint defines its own full path (e.g., `/.env`, `/api/v1/config/secrets`). This is intentional because bait paths need to look like they live in various parts of the API.

### Step 2 — Add Bait Paths to Gateway Config

In `api_gateway/core/config.py`, add these to **`BACKEND_ROUTES`** so the gateway knows to proxy them to the backend:

```python
"/.env": "http://localhost:8001",
"/api/graphql": "http://localhost:8001",
"/wp-admin": "http://localhost:8001",
"/actuator": "http://localhost:8001",
"/server-status": "http://localhost:8001",
```

And add these to **`DEPRECATED_PATHS`** so the gateway's risk scorer flags them as high-risk:

```python
"/.env", "/api/graphql", "/wp-admin/", "/actuator/",
"/server-status", "/api/v1/admin/backup/", "/api/v1/config/secrets",
"/api/v1/internal/ssh-keys", "/api/v1/debug/sql-console",
"/api/v1/admin/impersonate", "/api/v1/payments/refund-override",
"/api/v1/auth/tokens/refresh-all",
```

### Step 3 — Add Bait Traffic to Simulator (Optional)

In `traffic_sim.py`, add bait endpoints to the `ENDPOINTS` list with **low weights** so they fire occasionally to simulate hacker probing:

```python
# Bait / Honeypot — low weight, simulates occasional hacker probing
dict(method="GET",  path="/api/v1/admin/backup/db-dump",        tag="bait", auth=False, weight=0.4),
dict(method="GET",  path="/api/v1/config/secrets",              tag="bait", auth=False, weight=0.3),
dict(method="GET",  path="/.env",                               tag="bait", auth=False, weight=0.5),
dict(method="POST", path="/api/v1/debug/sql-console",           tag="bait", auth=False, weight=0.3,
     body=lambda: {"query": "SELECT * FROM users LIMIT 10"}),
# ... (add more as needed)
```

Also add `"bait"` to:
- `TAG_COLORS` dict (e.g., `"bait": "\033[41;97m"` for white-on-red)
- `stats["per_tag"]` dict
- Default `--tags` argument

### Step 4 — Remove Old Files

If you previously had the bait code at `app/bait/`, you can safely delete that folder:

```
app/bait/__init__.py    ← DELETE (moved to trapnet/)
app/bait/bait_api.py    ← DELETE (moved to trapnet/)
```

---

## Live Terminal UI (terminal.html)

A **zero-dependency, single-file** HTML page that provides a real-time event feed. No build step required.

### Features
- **WebSocket connection** to `ws://localhost:8000/ws/events` (auto-reconnects)
- **Color-coded event types:**
  - 🟢 Green = safe traffic
  - 🟡 Yellow = warnings / alerts
  - 🔴 Red = critical / incidents / blocked IPs
  - 🟣 Magenta = **bait trap hits** (highlighted)
  - 🟠 Orange = zombie API detections
- **Dropdown filters:** Event Type, Severity Level
- **Search box** for path or IP filtering
- **Pause/Resume/Clear** controls
- **Live stats strip:** Total, Safe, Warns, Critical, Traps, Zombies

### How to Use Standalone
Just open `terminal.html` in a browser. It auto-connects to the gateway WebSocket.

### How to Embed in Main Frontend (React/Next.js)
Use an iframe:

```html
<iframe src="/trapnet/terminal.html" width="100%" height="600" frameborder="0"></iframe>
```

Or port the WebSocket logic to your React component — the WebSocket message format is:

```json
{
  "type": "new_trap_hit",
  "data": {
    "bait": "db-dump",
    "path": "/api/v1/admin/backup/db-dump",
    "method": "GET",
    "source_ip": "127.0.0.1",
    "user_agent": "python-requests/2.31.0",
    "timestamp": "2026-06-25T18:30:00Z"
  }
}
```

Other event types from the WebSocket: `new_event`, `new_alert`, `new_incident`, `zombie_api_detected`, `new_block`, `dashboard_updated`.

---

## Internal Architecture (How `bait_api.py` Works)

```
Attacker Request
       │
       ▼
  Gateway (:8000)  ──► Risk Scorer flags path as deprecated/debug  ──► Redis event
       │
       ▼
  Backend (:8001)  ──► bait_api.py endpoint handler
       │
       ├── _simulate_processing()    →  Random 100-500ms delay (looks real)
       ├── _record_trap_hit()        →  Records alert + forensic data + WebSocket broadcast
       │       ├── repo.increment_trap_hit(path)
       │       ├── repo.insert_alert(severity="critical", ...)
       │       ├── repo.insert_forensic(payload=..., risk_score=0.95)
       │       └── broadcast("new_trap_hit", {...})
       │
       └── Return fake data          →  Convincing JSON/text response
```

### Dependencies
- `fastapi` (for APIRouter, Request, JSONResponse, PlainTextResponse)
- `api_gateway/db/repository.py` (lazy import — for `insert_alert`, `increment_trap_hit`, `insert_forensic`)
- `api_gateway/api/websocket.py` (lazy import — for `broadcast()`)

The lazy imports are wrapped in `try/except` so the bait endpoints still work even if the gateway DB or WebSocket modules aren't available.

---

## Quick Test

With the platform running:

```bash
# Hit a honeypot — should return fake DB data
curl http://localhost:8000/api/v1/admin/backup/db-dump

# Hit the .env bait — should return fake credentials
curl http://localhost:8000/.env

# Hit the SQL console
curl -X POST http://localhost:8000/api/v1/debug/sql-console \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users"}'
```

Each hit will:
- Return fake data (200 OK)
- Log `BAIT TRAP HIT` in the backend console
- Show up as a magenta `TRAP HIT` line in `terminal.html`
- Create a critical alert in the alerts API (`GET /api/alerts`)

---

## Changes Already Applied to the Alpha Branch

For reference, here are all the files that were modified as part of TrapNet on the `Alpha` branch:

| File | Change |
|------|--------|
| `app/main.py` | Added `from trapnet.bait_api import router as bait_router` + `app.include_router(bait_router)` |
| `api_gateway/core/config.py` | Added bait paths to `BACKEND_ROUTES` and `DEPRECATED_PATHS` |
| `traffic_sim.py` | Added 13 bait endpoints with low weights, `"bait"` tag color, stats counter |
| `run_all.bat` | Updated to open `terminal.html` automatically |

---

## Contact / Notes

- TrapNet is **fully self-contained** in this folder. The only external touchpoints are the router registration in `app/main.py` and the gateway config entries.
- All fake data is **randomly generated per request** — no two responses are identical.
- The `_record_trap_hit()` function uses lazy imports so it degrades gracefully if the gateway DB isn't reachable.
