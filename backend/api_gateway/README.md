# ☠ Zombie API Gateway
### *Zombie API Discovery & Defense — Hackathon Project*

A lightweight, modular intelligent API gateway built with **FastAPI + Redis Streams + asyncio**.
It detects shadow/zombie APIs in real-time, scores request risk, and blocks dangerous traffic.

---

## Architecture

```
Client / Simulator
       │
       ▼
┌─────────────────────┐
│   Zombie Gateway    │  ← FastAPI + Middleware stack
│   (main.py)         │
│                     │
│  CorrelationID MW   │
│  RequestLogging MW  │
│  SecurityHeaders MW │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   Risk Engine       │  ← 8 detection rules, risk score 0–1
│   (risk_engine.py)  │
│                     │
│  • undocumented     │
│  • deprecated       │
│  • debug route      │
│  • missing auth     │
│  • internal route   │
│  • abnormal freq    │
│  • high error rate  │
│  • suspicious UA    │
└──────────┬──────────┘
           │
    ┌──────┴──────┐
    │             │
    ▼             ▼
BLOCKED      Forward via
(403)        httpx async
             (proxy_handler.py)
                  │
                  ▼
         Backend Microservices
         :9001 users
         :9002 products
         :9003 orders
         :9004 internal
           │
           ▼
    Redis Streams
    zombie:requests
           │
           ▼
    Brain Worker
    (brain_worker.py)
    ← secondary analysis
    ← IP intelligence
    ← threat alerts
```

---

## Quick Start (Local)

### Prerequisites
- Python 3.11+
- Redis running on localhost:6379

```bash
# 1. Clone / enter project
cd backend

# 2. Create virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy env config
cp .env.example .env

# 5. Start Redis (if not running)
redis-server --daemonize yes

# 6. Start the Banking Backend (terminal 1)
# Uses the real backend at app/main.py
python app/main.py

# 7. Start the Gateway (terminal 2)
python scripts/main.py

# 8. Start the Brain Engine worker (terminal 3)
python scripts/brain_worker.py

# 9. Run the traffic simulator (terminal 4)
# Uses the top-level traffic_sim.py provided in the repo root
python traffic_sim.py
```

---

## Quick Start (Docker)

```bash
# Build and start everything
docker-compose up --build

# Or in background
docker-compose up --build -d

# Watch logs
docker-compose logs -f gateway
docker-compose logs -f brain-worker

# Stop
docker-compose down
```

---

## Monitoring Endpoints

| Endpoint | Description |
|---|---|
| `GET /health` | Basic liveness check |
| `GET /status` | Gateway + Redis full status |
| `GET /dashboard` | Live HTML dashboard (auto-refreshes) |
| `GET /zombies` | All detected zombie endpoints |
| `GET /events?limit=50` | Recent stream events |
| `GET /counters` | Request counters + block rate |
| `GET /metrics` | Prometheus text format |
| `GET /risk/score?path=/api/v1/test` | Ad-hoc risk score |
| `DELETE /zombies/{path}` | Clear a zombie record (requires `X-Dashboard-Key` header) |
| `GET /docs` | OpenAPI interactive docs |

---

## Example API Requests

### 1. Health check
```bash
curl http://localhost:8000/health
```

### 2. Normal authenticated request (ALLOWED)
```bash
curl http://localhost:8000/api/users \
  -H "Authorization: Bearer mytoken123"
```

### 3. Deprecated endpoint (WARNED/BLOCKED)
```bash
curl http://localhost:8000/api/v1/users
# Response: 403 + {"error":"Request blocked","flags":["deprecated_endpoint"]}
```

### 4. Debug route probe (BLOCKED)
```bash
curl http://localhost:8000/.env
curl http://localhost:8000/debug
curl http://localhost:8000/actuator/env
```

### 5. Missing auth on protected route (WARNED)
```bash
curl http://localhost:8000/api/products
# X-Zombie-Score: 0.35+, X-Zombie-Flags: missing_auth
```

### 6. Internal route without service token (BLOCKED)
```bash
curl http://localhost:8000/api/internal/config
```

### 7. Internal route WITH service token (lower risk)
```bash
curl http://localhost:8000/api/internal/config \
  -H "x-service-token: valid-internal-token"
```

### 8. Scanner bot (BLOCKED)
```bash
curl http://localhost:8000/api/users \
  -H "User-Agent: sqlmap/1.7.3"
```

### 9. Ad-hoc risk score check
```bash
curl "http://localhost:8000/risk/score?path=/api/v1/legacy&method=GET"
```

### 10. View zombie endpoints
```bash
curl http://localhost:8000/zombies | python -m json.tool
```

### 11. View recent events
```bash
curl http://localhost:8000/events?limit=20 | python -m json.tool
```

### 12. Prometheus metrics
```bash
curl http://localhost:8000/metrics
```

### 13. Clear a zombie record
```bash
curl -X DELETE http://localhost:8000/zombies/api/v1/users \
  -H "X-Dashboard-Key: zombie-dashboard"
```

---

## Detection Rules

| Rule | Score Contribution | Trigger |
|---|---|---|
| `undocumented_endpoint` | +0.35 | Path not in known prefixes |
| `deprecated_endpoint` | +0.45 | Path matches deprecated patterns |
| `debug_route_access` | +0.55 | Debug/actuator/env paths |
| `internal_route_no_s2s_token` | +0.50 | Internal path, no service token |
| `missing_auth` | +0.40 | Auth-required path, no credentials |
| `abnormal_frequency` | +0.20–0.60 | Exceeds rate limit window |
| `high_error_rate` | +0.20–0.45 | >60% errors on path in 5 min |
| `suspicious_user_agent` | +0.20–0.65 | Known scanner/attack tool UA |

**Score ≥ 0.75** → Request BLOCKED (HTTP 403)  
**Score ≥ 0.40** → Request WARNED (forwarded with flag headers)  
**Score < 0.40** → Request ALLOWED

---

## Project Structure

```
zombie-gateway/
├── gateway/
│   ├── app.py                 # FastAPI app + lifespan
│   ├── middleware.py          # Correlation ID, logging, security headers
│   └── proxy.py               # Async reverse proxy + metadata writes
├── brain/
│   ├── engine.py              # Redis event consumer + SQLite intelligence writes
│   └── worker.py              # Background consumer loop
├── db/
│   ├── database.py            # Lightweight SQLite connection helpers
│   ├── db_helpers.py          # Metadata upserts, queries, cleanup
│   └── schema.sql             # Auto-created tables and indexes
├── monitoring/
│   └── router.py              # Gateway + DB monitoring endpoints
├── scripts/
│   ├── main.py                # Compatibility wrapper entrypoint (gateway)
│   └── run_local.py           # Combined local runner (gateway + brain)
├── main.py                    # Compatibility wrapper entrypoint
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── app/
│   ├── __init__.py
│   ├── config.py              # All settings (pydantic-settings)
│   ├── middleware.py          # Correlation ID, logging, security headers
│   ├── redis_client.py        # Redis pool, stream helpers, counters
│   ├── proxy_handler.py       # Async reverse proxy (httpx)
│   ├── risk_engine.py         # 8 zombie detection rules + scorer
│   └── monitoring.py          # All monitoring/dashboard endpoints
├── workers/
│   ├── __init__.py
│   └── brain_worker.py        # Redis Stream consumer + IP intelligence
└── app compatibility wrappers  # legacy thin wrappers kept for imports

├── scripts/
│   ├── main.py                # Compatibility wrapper entrypoint
│   ├── mock_backend.py        # 4 mock microservices (ports 9001–9004)
│   └── simulate_traffic.py    # Traffic simulator with attack scenarios
└── legacy compatibility wrappers kept inside `scripts/`

### Persisted tables
- `detected_apis`
- `request_events`
- `zombie_endpoints`
- `alerts`
- `ip_intelligence`

### New monitoring endpoints
- `GET /db/zombies`
- `GET /db/alerts`
- `GET /db/top-risk-apis`
- `GET /db/stats`

### Example queries
```bash
sqlite3 data/zombie_gateway.sqlite3 "SELECT endpoint, risk_score, status FROM detected_apis ORDER BY risk_score DESC LIMIT 10;"
sqlite3 data/zombie_gateway.sqlite3 "SELECT ip, blocked_requests, threat_level FROM ip_intelligence ORDER BY blocked_requests DESC LIMIT 10;"
sqlite3 data/zombie_gateway.sqlite3 "SELECT alert_type, severity, endpoint, ip, timestamp FROM alerts ORDER BY timestamp DESC LIMIT 20;"
```
```

---

## Hackathon Notes

- **Zero external deps beyond Redis** — runs on any laptop
- **Redis Streams** provide durable, replayable event log
- **Brain Worker** runs independently, can be scaled horizontally
- Add more backends in `.env` via `BACKEND_ROUTES` JSON
- Thresholds tunable via env vars — no code change needed
- Prometheus `/metrics` plugs into any Grafana setup
