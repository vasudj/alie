"""
ALIE — Level 1 AI Risk Scoring Engine
======================================
Part 2 of the ALIE 5-part security pipeline.

Sits directly behind the API Gateway's Log Scaler-Downer (Part 1).
Reads `scaled_down_audit.log` (JSON lines) every 10 seconds, groups
telemetry by API path, runs lightweight statistical analysis, and
exposes risk scores for downstream Level 2 / Level 3 engines to consume.

Log schema produced by Part 1 (gateway/middleware.py):
  {
      "timestamp":      "2024-01-01T12:00:00Z",   # ISO-8601 UTC
      "method":         "GET",
      "path":           "/api/v1/reports/legacy-ledger",
      "source_ip":      "10.0.0.1",
      "status_code":    200,
      "latency_ms":     43.2,
      "request_bytes":  0,
      "response_bytes": 54320            # 0 when upstream omits Content-Length
  }

Run:
  python level1_ai_engine.py [--log path/to/scaled_down_audit.log] [--port 8002]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import statistics
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

LOG_FILE_DEFAULT = Path("scaled_down_audit.log")
BATCH_INTERVAL_S = 10          # how often the background processor runs

# Scoring thresholds
VELOCITY_SPIKE_RPM   = 100     # requests per minute
VELOCITY_SPIKE_SCORE = 20

ERROR_RATE_THRESHOLD = 0.10    # 10 %
ERROR_RATE_SCORE     = 25

PAYLOAD_VOLATILITY_THRESHOLD = 10_000   # std-dev bytes
PAYLOAD_VOLATILITY_SCORE     = 50

BASE_SCORE  = 5
MAX_SCORE   = 100

# ─────────────────────────────────────────────────────────────────────────────
# In-memory state  (written by the background processor, read by API handlers)
# ─────────────────────────────────────────────────────────────────────────────

class EndpointRisk(BaseModel):
    path:               str
    risk_score:         int
    velocity_rpm:       float
    error_rate:         float          # 0.0 – 1.0
    payload_volatility: float          # std-dev of response_bytes
    mean_response_bytes: float
    mean_latency_ms:    float
    sample_count:       int
    flags:              List[str]
    last_seen:          Optional[str]  # ISO-8601


# Keyed by path string.
_risk_store: Dict[str, EndpointRisk] = {}
_store_lock  = asyncio.Lock()
_last_run_at: Optional[str] = None
_log_file    = LOG_FILE_DEFAULT


# ─────────────────────────────────────────────────────────────────────────────
# Log parsing
# ─────────────────────────────────────────────────────────────────────────────

def _parse_log(log_path: Path) -> List[Dict[str, Any]]:
    """Read the JSON-lines audit log and return a list of valid record dicts.

    Tolerates:
      - Missing file (gateway hasn't started yet).
      - Truncated/malformed lines (skipped silently).
      - Legacy field names from earlier gateway versions (`source_ip` vs
        `client_ip`, `payload_size_bytes` vs `request_bytes`).
    """
    if not log_path.exists():
        return []

    records: List[Dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Normalise field aliases so the rest of the engine is uniform.
            if "client_ip" not in rec:
                rec["client_ip"] = rec.get("source_ip", "unknown")
            if "request_bytes" not in rec:
                rec["request_bytes"] = rec.get("payload_size_bytes", 0)
            if "response_bytes" not in rec:
                rec["response_bytes"] = 0

            # Coerce numeric types defensively.
            try:
                rec["status_code"]    = int(rec.get("status_code", 0))
                rec["latency_ms"]     = float(rec.get("latency_ms", 0.0))
                rec["request_bytes"]  = int(rec.get("request_bytes", 0))
                rec["response_bytes"] = int(rec.get("response_bytes", 0))
            except (TypeError, ValueError):
                continue

            if not rec.get("path"):
                continue

            records.append(rec)

    return records


# ─────────────────────────────────────────────────────────────────────────────
# Statistical helpers
# ─────────────────────────────────────────────────────────────────────────────

def _safe_stdev(values: List[float]) -> float:
    """Population stdev; returns 0.0 for < 2 samples."""
    if len(values) < 2:
        return 0.0
    try:
        return statistics.pstdev(values)
    except statistics.StatisticsError:
        return 0.0


def _safe_mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return statistics.mean(values)


def _velocity_rpm(timestamps: List[str]) -> float:
    """Convert a list of ISO-8601 timestamp strings into requests/minute.

    Uses the span between the earliest and latest observation.
    Falls back to len(timestamps) / 1.0 if the window is < 1 second.
    """
    if len(timestamps) < 2:
        return float(len(timestamps))

    parsed: List[float] = []
    for ts in timestamps:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            parsed.append(dt.timestamp())
        except ValueError:
            continue

    if len(parsed) < 2:
        return float(len(timestamps))

    window_s = max(parsed) - min(parsed)
    if window_s < 1.0:
        # All requests arrived in under a second — treat as a spike.
        return float(len(parsed)) * 60.0

    return (len(parsed) / window_s) * 60.0


# ─────────────────────────────────────────────────────────────────────────────
# Core scoring algorithm
# ─────────────────────────────────────────────────────────────────────────────

def _score_endpoint(
    path: str,
    records: List[Dict[str, Any]],
) -> EndpointRisk:
    """
    Calculate risk score and supporting metrics for a single API endpoint.

    Scoring matrix:
      Base score                                         :  +5
      Velocity spike  (> 100 req/min)                   : +20
      High error rate (> 10 % 4xx/5xx)                  : +25
      Payload volatility (stdev response_bytes > 10 KB) : +50
      Maximum cap                                        : 100
    """
    timestamps     = [r.get("timestamp", "") for r in records]
    status_codes   = [r["status_code"] for r in records]
    latencies      = [r["latency_ms"] for r in records]
    resp_bytes     = [float(r["response_bytes"]) for r in records]

    n              = len(records)
    velocity       = _velocity_rpm(timestamps)
    error_count    = sum(1 for s in status_codes if s >= 400)
    error_rate     = error_count / n if n > 0 else 0.0
    payload_stdev  = _safe_stdev(resp_bytes)
    mean_resp      = _safe_mean(resp_bytes)
    mean_lat       = _safe_mean(latencies)
    last_seen      = max(timestamps) if timestamps else None

    score = BASE_SCORE
    flags: List[str] = []

    if velocity > VELOCITY_SPIKE_RPM:
        score += VELOCITY_SPIKE_SCORE
        flags.append(f"VELOCITY_SPIKE({velocity:.1f} rpm)")

    if error_rate > ERROR_RATE_THRESHOLD:
        score += ERROR_RATE_SCORE
        flags.append(f"HIGH_ERROR_RATE({error_rate*100:.1f}%)")

    if payload_stdev > PAYLOAD_VOLATILITY_THRESHOLD:
        score += PAYLOAD_VOLATILITY_SCORE
        flags.append(f"PAYLOAD_VOLATILITY(stdev={payload_stdev:.0f}B)")

    score = min(score, MAX_SCORE)

    return EndpointRisk(
        path=path,
        risk_score=score,
        velocity_rpm=round(velocity, 2),
        error_rate=round(error_rate, 4),
        payload_volatility=round(payload_stdev, 2),
        mean_response_bytes=round(mean_resp, 2),
        mean_latency_ms=round(mean_lat, 2),
        sample_count=n,
        flags=flags,
        last_seen=last_seen,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Background batch processor
# ─────────────────────────────────────────────────────────────────────────────

async def _batch_processor() -> None:
    """Runs every BATCH_INTERVAL_S seconds. Reads the log, scores every
    endpoint, and atomically replaces the in-memory risk store."""
    global _last_run_at

    while True:
        await asyncio.sleep(BATCH_INTERVAL_S)
        run_start = time.monotonic()

        try:
            records = await asyncio.to_thread(_parse_log, _log_file)
        except Exception as exc:
            print(f"[WARN] Log read failed: {exc}")
            continue

        # Group by path.
        by_path: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for rec in records:
            by_path[rec["path"]].append(rec)

        # Score each endpoint (CPU-bound but tiny for a PoC — no thread needed).
        new_store: Dict[str, EndpointRisk] = {}
        for path, path_records in by_path.items():
            new_store[path] = _score_endpoint(path, path_records)

        elapsed_ms = round((time.monotonic() - run_start) * 1000, 1)
        _last_run_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

        async with _store_lock:
            _risk_store.clear()
            _risk_store.update(new_store)

        total_records = len(records)
        high_risk = sum(1 for r in new_store.values() if r.risk_score >= 50)
        print(
            f"[{_last_run_at}] Batch complete — "
            f"{total_records} records, {len(new_store)} endpoints scored, "
            f"{high_risk} high-risk (≥50)  [{elapsed_ms}ms]"
        )

        # Emit a compact risk table to stdout for live visibility.
        if new_store:
            print(f"  {'PATH':<52}  {'SCORE':>5}  {'VEL(rpm)':>9}  "
                  f"{'ERR%':>5}  {'STDEV-B':>9}  FLAGS")
            print(f"  {'─'*52}  {'─'*5}  {'─'*9}  {'─'*5}  {'─'*9}  {'─'*30}")
            for ep in sorted(new_store.values(), key=lambda x: -x.risk_score):
                flag_str = ", ".join(ep.flags) if ep.flags else "—"
                score_tag = (
                    "\033[91m" if ep.risk_score >= 75 else
                    "\033[93m" if ep.risk_score >= 40 else
                    "\033[92m"
                ) + f"{ep.risk_score:>3}" + "\033[0m"
                print(
                    f"  {ep.path:<52}  {score_tag}/100"
                    f"  {ep.velocity_rpm:>9.1f}"
                    f"  {ep.error_rate*100:>4.1f}%"
                    f"  {ep.payload_volatility:>9.0f}"
                    f"  {flag_str}"
                )
            print()


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI application
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ALIE Level 1 — AI Risk Scoring Engine",
    description=(
        "Statistical anomaly detection on raw API telemetry. "
        "Scores each endpoint 0–100 based on velocity, error rate, "
        "and payload volatility. Feeds Level 2 and Level 3 engines."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


@app.on_event("startup")
async def _startup() -> None:
    asyncio.create_task(_batch_processor())
    print(
        f"[ALIE L1] Risk Scoring Engine started.\n"
        f"  Log file      : {_log_file.resolve()}\n"
        f"  Batch interval: {BATCH_INTERVAL_S}s\n"
        f"  Thresholds    : velocity>{VELOCITY_SPIKE_RPM}rpm  "
        f"error>{ERROR_RATE_THRESHOLD*100:.0f}%  "
        f"stdev>{PAYLOAD_VOLATILITY_THRESHOLD}B\n"
    )


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
async def health() -> dict:
    async with _store_lock:
        endpoint_count = len(_risk_store)
    return {
        "status":          "healthy",
        "service":         "alie-level1-ai-engine",
        "version":         "1.0.0",
        "log_file":        str(_log_file),
        "batch_interval_s": BATCH_INTERVAL_S,
        "endpoints_tracked": endpoint_count,
        "last_batch_at":   _last_run_at,
        "timestamp":       datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


# ── Risk Scores ───────────────────────────────────────────────────────────────

@app.get("/api/v1/risk-scores", tags=["scoring"])
async def get_risk_scores(
    min_score: int = 0,
    path_contains: Optional[str] = None,
) -> JSONResponse:
    """
    Return the current risk assessment for every tracked API endpoint.

    Query parameters
    ----------------
    min_score      : Only return endpoints with risk_score >= this value (default 0).
    path_contains  : Filter by substring in the path.
    """
    async with _store_lock:
        snapshot = dict(_risk_store)

    if not snapshot:
        return JSONResponse(
            status_code=200,
            content={
                "message": "No data yet — waiting for first batch cycle.",
                "hint": f"The engine processes {_log_file} every {BATCH_INTERVAL_S}s.",
                "endpoints": {},
            },
        )

    filtered = {
        path: ep.dict()
        for path, ep in snapshot.items()
        if ep.risk_score >= min_score
        and (path_contains is None or path_contains in path)
    }

    high_risk   = [p for p, ep in snapshot.items() if ep.risk_score >= 75]
    medium_risk = [p for p, ep in snapshot.items() if 40 <= ep.risk_score < 75]
    low_risk    = [p for p, ep in snapshot.items() if ep.risk_score < 40]

    return JSONResponse(
        status_code=200,
        content={
            "generated_at":    datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "last_batch_at":   _last_run_at,
            "total_endpoints": len(snapshot),
            "returned":        len(filtered),
            "summary": {
                "high_risk_count":   len(high_risk),
                "medium_risk_count": len(medium_risk),
                "low_risk_count":    len(low_risk),
                "high_risk_paths":   high_risk,
            },
            "endpoints": filtered,
        },
    )


# ── Single-endpoint detail ────────────────────────────────────────────────────

@app.get("/api/v1/risk-scores/path", tags=["scoring"])
async def get_risk_score_for_path(path: str) -> JSONResponse:
    """
    Return the risk assessment for a specific API path.

    Example: GET /api/v1/risk-scores/path?path=/api/v1/reports/legacy-ledger
    """
    async with _store_lock:
        ep = _risk_store.get(path)

    if ep is None:
        return JSONResponse(
            status_code=404,
            content={"error": f"No data for path '{path}'.", "tracked_paths": list(_risk_store.keys())},
        )
    return JSONResponse(status_code=200, content=ep.dict())


# ── Trigger immediate batch run ───────────────────────────────────────────────

@app.post("/api/v1/run-batch", tags=["ops"])
async def trigger_batch() -> dict:
    """Force an immediate out-of-cycle batch analysis run."""
    run_start = time.monotonic()
    try:
        records = await asyncio.to_thread(_parse_log, _log_file)
    except Exception as exc:
        return {"status": "error", "detail": str(exc)}

    by_path: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for rec in records:
        by_path[rec["path"]].append(rec)

    new_store: Dict[str, EndpointRisk] = {}
    for path, path_records in by_path.items():
        new_store[path] = _score_endpoint(path, path_records)

    global _last_run_at
    _last_run_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    async with _store_lock:
        _risk_store.clear()
        _risk_store.update(new_store)

    elapsed_ms = round((time.monotonic() - run_start) * 1000, 1)
    return {
        "status":           "ok",
        "elapsed_ms":       elapsed_ms,
        "records_parsed":   len(records),
        "endpoints_scored": len(new_store),
        "completed_at":     _last_run_at,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ALIE Level 1 — AI Risk Scoring Engine"
    )
    parser.add_argument(
        "--log",
        default=str(LOG_FILE_DEFAULT),
        help=f"Path to the audit log produced by the gateway (default: {LOG_FILE_DEFAULT})",
    )
    parser.add_argument(
        "--port",
        default=8002,
        type=int,
        help="Port to listen on (default: 8002)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Bind host (default: 0.0.0.0)",
    )
    args = parser.parse_args()

    _log_file = Path(args.log)

    uvicorn.run(
        "level1_ai_engine:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="warning",   # suppress uvicorn noise; engine prints its own table
    )
