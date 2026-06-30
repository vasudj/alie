"""
ALIE Traffic Simulator — async edition
=======================================
Generates three concurrent attack/legitimate traffic profiles against the
API Gateway using asyncio + aiohttp.

Profiles
--------
  A  Legitimate   High-volume standard /api/v2/transfer requests (normal users).
  B  Volumetric   Sudden burst of requests from a spoofed source IP to test
                  Level 2 rate-limiting and DDoS detection.
  C  Zombie       Low-and-slow requests to the deprecated /api/v1/reports/legacy-ledger
                  endpoint — simulates a forgotten batch service generating massive
                  payloads that Level 1 AI detects via historical batch analysis.

Run
---
  python traffic_sim.py [--url http://localhost:8000]
                        [--duration 120]
                        [--profiles A,B,C]
                        [--rps-a 20] [--rps-b 80] [--interval-c 8]
"""

from __future__ import annotations

import argparse
import asyncio
import math
import random
import time
from datetime import datetime, timezone
from typing import Optional

import aiohttp

# ─────────────────────────────────────────────────────────────────────────────
# ANSI palette
# ─────────────────────────────────────────────────────────────────────────────
R       = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"

PROFILE_COLOR = {"A": GREEN, "B": RED, "C": MAGENTA}

def _sc(code: int) -> str:
    if code == 0:
        return RED
    if 200 <= code < 300:
        return GREEN
    if 300 <= code < 400:
        return CYAN
    if 400 <= code < 500:
        return YELLOW
    return RED


# ─────────────────────────────────────────────────────────────────────────────
# Shared stats
# ─────────────────────────────────────────────────────────────────────────────
_stats: dict[str, dict] = {
    "A": {"ok": 0, "err": 0, "total": 0, "latencies": []},
    "B": {"ok": 0, "err": 0, "total": 0, "latencies": []},
    "C": {"ok": 0, "err": 0, "total": 0, "latencies": []},
}
_stats_lock = asyncio.Lock()


async def _record(profile: str, status: int, latency_ms: float) -> None:
    async with _stats_lock:
        bucket = _stats[profile]
        bucket["total"] += 1
        bucket["latencies"].append(latency_ms)
        if len(bucket["latencies"]) > 1000:
            bucket["latencies"] = bucket["latencies"][-1000:]
        if 200 <= status < 300:
            bucket["ok"] += 1
        else:
            bucket["err"] += 1


def _p95(latencies: list[float]) -> float:
    if not latencies:
        return 0.0
    s = sorted(latencies)
    idx = max(0, math.ceil(len(s) * 0.95) - 1)
    return round(s[idx], 1)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _print_row(profile: str, method: str, path: str, status: int, ms: float,
               note: str = "") -> None:
    pc  = PROFILE_COLOR.get(profile, "")
    stc = _sc(status)
    sc_str = str(status) if status else "ERR"
    note_str = f"  {DIM}{note}{R}" if note else ""
    print(
        f"  {DIM}{_now()}{R}  "
        f"{pc}[{profile}]{R}  "
        f"{BOLD}{method:<6}{R}  "
        f"{path:<52}  "
        f"{stc}{sc_str:<6}{R}  "
        f"{DIM}{ms:>6.0f}ms{R}"
        f"{note_str}"
    )


async def _fire(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    profile: str,
    extra_headers: Optional[dict] = None,
    json_body: Optional[dict] = None,
    note: str = "",
) -> tuple[int, float]:
    headers = {"Content-Type": "application/json"}
    if extra_headers:
        headers.update(extra_headers)

    t0 = time.monotonic()
    status = 0
    try:
        async with session.request(method, url, headers=headers, json=json_body, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            status = resp.status
            await resp.read()   # drain body so connection returns to pool
    except asyncio.TimeoutError:
        status = 408
    except aiohttp.ClientConnectorError:
        status = 0
    except Exception:
        status = 0

    ms = round((time.monotonic() - t0) * 1000, 1)
    path = url.split("://", 1)[-1].split("/", 1)[-1]
    path = "/" + path if not path.startswith("/") else path
    _print_row(profile, method, path, status, ms, note)
    await _record(profile, status, ms)
    return status, ms


# ─────────────────────────────────────────────────────────────────────────────
# Profile A — Legitimate high-volume traffic
# ─────────────────────────────────────────────────────────────────────────────

_LEGITIMATE_ACCOUNTS = [f"ACC-{i:06d}" for i in range(1, 51)]
_LEGITIMATE_USERS = [
    {"email": "john.doe@example.com",  "password": "password123"},
    {"email": "jane.smith@example.com", "password": "password123"},
    {"email": "bob.wilson@example.com", "password": "password123"},
]


async def _profile_a_worker(base_url: str, target_rps: float, stop: asyncio.Event) -> None:
    """Legitimate users — balanced mix of login + balance check + transfer."""
    connector = aiohttp.TCPConnector(limit=50)
    async with aiohttp.ClientSession(connector=connector) as session:
        interval = max(0.02, 1.0 / max(0.1, target_rps))
        token: Optional[str] = None

        while not stop.is_set():
            # Refresh token if missing
            if not token:
                user = random.choice(_LEGITIMATE_USERS)
                status, _ = await _fire(
                    session, "POST",
                    f"{base_url}/api/v2/auth/login",
                    "A", json_body=user, note="login"
                )
                # Token management is simulated; gateway just sees traffic.
                token = "sim-token-placeholder" if status == 200 else None
                await asyncio.sleep(interval)
                continue

            action = random.choices(
                ["transfer", "balance", "txn_list"],
                weights=[60, 25, 15],
            )[0]

            if action == "transfer":
                src, dst = random.sample(_LEGITIMATE_ACCOUNTS, 2)
                await _fire(
                    session, "POST",
                    f"{base_url}/api/v2/transfer",
                    "A",
                    extra_headers={"Authorization": f"Bearer {token}"},
                    json_body={
                        "from_account": src,
                        "to_account":   dst,
                        "amount":       round(random.uniform(10, 5000), 2),
                        "currency":     "USD",
                        "reference":    f"REF-{random.randint(100000,999999)}",
                    },
                    note="transfer",
                )

            elif action == "balance":
                await _fire(
                    session, "GET",
                    f"{base_url}/api/v2/accounts/balance",
                    "A",
                    extra_headers={"Authorization": f"Bearer {token}"},
                    note="balance",
                )

            else:
                await _fire(
                    session, "GET",
                    f"{base_url}/api/v2/transactions",
                    "A",
                    extra_headers={"Authorization": f"Bearer {token}"},
                    note="txn_list",
                )

            # Randomise inter-request interval to simulate real user variance.
            jitter = random.uniform(0.7, 1.4)
            await asyncio.sleep(interval * jitter)


# ─────────────────────────────────────────────────────────────────────────────
# Profile B — Volumetric DoS burst
# ─────────────────────────────────────────────────────────────────────────────

_SPOOFED_IP = "10.66.66.66"   # injected via X-Forwarded-For to emulate spoofing
_DOS_ENDPOINTS = [
    "/api/v2/accounts/balance",
    "/api/v2/transactions",
    "/api/v2/auth/login",
]


async def _profile_b_burst(base_url: str, concurrency: int, stop: asyncio.Event) -> None:
    """Volumetric DoS — sends massive parallel bursts from a single spoofed IP."""
    connector = aiohttp.TCPConnector(limit=concurrency + 10)
    async with aiohttp.ClientSession(connector=connector) as session:
        while not stop.is_set():
            # Each cycle: fire `concurrency` requests simultaneously.
            tasks = [
                _fire(
                    session, "GET",
                    base_url + random.choice(_DOS_ENDPOINTS),
                    "B",
                    extra_headers={
                        "X-Forwarded-For": _SPOOFED_IP,
                        "X-Real-IP":       _SPOOFED_IP,
                        "User-Agent":      "python-aiohttp/dos-sim",
                    },
                    note=f"burst×{concurrency} from {_SPOOFED_IP}",
                )
                for _ in range(concurrency)
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

            # Short pause between bursts so the pattern is clearly burst-shaped.
            await asyncio.sleep(random.uniform(1.5, 3.5))


# ─────────────────────────────────────────────────────────────────────────────
# Profile C — Zombie scraper (low-and-slow)
# ─────────────────────────────────────────────────────────────────────────────

_ZOMBIE_PATH = "/api/v1/reports/legacy-ledger"


async def _profile_c_zombie(base_url: str, interval_s: float, stop: asyncio.Event) -> None:
    """
    Low-and-slow zombie scraper.  Mimics a forgotten internal batch service that
    woke up and now hits the deprecated legacy-ledger endpoint every few seconds,
    each time pulling a 50 KB+ response.  Level 1 AI detects this via:
      - Payload size anomaly (response >> request)
      - Endpoint matches deprecated v1 pattern
      - Low frequency but consistent cadence (batch signature)
    """
    connector = aiohttp.TCPConnector(limit=2)
    async with aiohttp.ClientSession(connector=connector) as session:
        while not stop.is_set():
            await _fire(
                session, "GET",
                base_url + _ZOMBIE_PATH,
                "C",
                extra_headers={
                    "User-Agent":    "internal-batch-reconciler/1.0 (deprecated)",
                    "X-Service-ID":  "batch-scheduler-legacy",
                    "X-Batch-Run":   str(int(time.time())),
                },
                note="zombie scrape — 50KB+ payload expected",
            )
            # Low-and-slow: long, slightly randomised sleep between requests.
            await asyncio.sleep(interval_s * random.uniform(0.8, 1.3))


# ─────────────────────────────────────────────────────────────────────────────
# Stats printer
# ─────────────────────────────────────────────────────────────────────────────

async def _stats_printer(stop: asyncio.Event, interval_s: float = 10.0) -> None:
    await asyncio.sleep(interval_s)
    while not stop.is_set():
        async with _stats_lock:
            snapshot = {k: dict(v) for k, v in _stats.items()}

        print(f"\n{BOLD}{'─'*74}{R}")
        print(f"  {BOLD}ALIE Traffic Simulator — Stats snapshot @ {_now()}{R}")
        print(f"  {'Profile':<10}  {'Total':>6}  {'OK':>6}  {'Err':>6}  {'OK%':>5}  {'p95 ms':>8}")
        print(f"  {'─'*10}  {'─'*6}  {'─'*6}  {'─'*6}  {'─'*5}  {'─'*8}")
        for p, label in [("A", "Legitimate"), ("B", "Volumetric"), ("C", "Zombie")]:
            b = snapshot[p]
            total = b["total"]
            ok    = b["ok"]
            err   = b["err"]
            pct   = round(ok / total * 100) if total else 0
            p95   = _p95(b["latencies"])
            pc    = PROFILE_COLOR.get(p, "")
            print(
                f"  {pc}{p} {label:<9}{R}  "
                f"{total:>6}  {GREEN}{ok:>6}{R}  {RED}{err:>6}{R}  "
                f"{pct:>4}%  {DIM}{p95:>7.1f}ms{R}"
            )
        print(f"{BOLD}{'─'*74}{R}\n")
        await asyncio.sleep(interval_s)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

async def main(
    base_url: str,
    duration: int,
    profiles: set[str],
    rps_a: float,
    rps_b_concurrency: int,
    interval_c: float,
) -> None:
    print(f"\n{BOLD}{'═'*74}{R}")
    print(f"  {BOLD}ALIE Advanced Traffic Simulator (asyncio + aiohttp){R}")
    print(f"{'═'*74}")
    print(f"  Target   : {CYAN}{base_url}{R}")
    print(f"  Profiles : {', '.join(sorted(profiles))}")
    print(f"  Duration : {'∞' if duration == 0 else str(duration) + 's'}")
    if "A" in profiles:
        print(f"  [A] Legitimate  — {rps_a:.1f} RPS  →  /api/v2/transfer (and balance/txn)")
    if "B" in profiles:
        print(f"  [B] Volumetric  — {rps_b_concurrency} parallel req/burst  X-Forwarded-For: {_SPOOFED_IP}")
    if "C" in profiles:
        print(f"  [C] Zombie      — 1 req / {interval_c}s  →  {_ZOMBIE_PATH}")
    print(f"{'═'*74}")
    print(f"  {'TIME':8}  {'PRF':5}  {'METHOD':<6}  {'PATH':<52}  {'CODE':<6}  {'MS':>6}")
    print(f"  {'─'*8}  {'─'*5}  {'─'*6}  {'─'*52}  {'─'*6}  {'─'*6}\n")

    stop = asyncio.Event()
    tasks: list[asyncio.Task] = []

    if "A" in profiles:
        tasks.append(asyncio.create_task(_profile_a_worker(base_url, rps_a, stop)))

    if "B" in profiles:
        tasks.append(asyncio.create_task(_profile_b_burst(base_url, rps_b_concurrency, stop)))

    if "C" in profiles:
        tasks.append(asyncio.create_task(_profile_c_zombie(base_url, interval_c, stop)))

    tasks.append(asyncio.create_task(_stats_printer(stop)))

    try:
        if duration > 0:
            await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=duration)
        else:
            await asyncio.gather(*tasks, return_exceptions=True)
    except (asyncio.TimeoutError, KeyboardInterrupt):
        pass
    finally:
        stop.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    # Final summary
    print(f"\n{BOLD}{'═'*74}{R}")
    print(f"  {BOLD}Final Summary{R}")
    async with _stats_lock:
        for p, label in [("A", "Legitimate"), ("B", "Volumetric"), ("C", "Zombie")]:
            if p not in profiles:
                continue
            b = _stats[p]
            total = b["total"]
            ok    = b["ok"]
            err   = b["err"]
            pct   = round(ok / total * 100) if total else 0
            p95   = _p95(b["latencies"])
            pc    = PROFILE_COLOR.get(p, "")
            print(
                f"  {pc}[{p}] {label:<10}{R}  "
                f"total={total}  ok={GREEN}{ok}{R}  err={RED}{err}{R}  "
                f"ok%={pct}  p95={DIM}{p95}ms{R}"
            )
    print(f"{BOLD}{'═'*74}{R}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ALIE async traffic simulator — generates A/B/C security test profiles."
    )
    parser.add_argument(
        "--url", default="http://localhost:8000",
        help="Base URL of the API Gateway (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--duration", default=0, type=int,
        help="Run duration in seconds; 0 = infinite (default: 0)",
    )
    parser.add_argument(
        "--profiles", default="A,B,C",
        help="Comma-separated profiles to enable: A,B,C (default: A,B,C)",
    )
    parser.add_argument(
        "--rps-a", default=20.0, type=float,
        help="[Profile A] Target requests/sec for legitimate traffic (default: 20)",
    )
    parser.add_argument(
        "--rps-b", default=80, type=int,
        help="[Profile B] Concurrent requests per burst for volumetric DoS (default: 80)",
    )
    parser.add_argument(
        "--interval-c", default=8.0, type=float,
        help="[Profile C] Seconds between zombie scrape requests (default: 8)",
    )
    args = parser.parse_args()

    asyncio.run(
        main(
            base_url=args.url.rstrip("/"),
            duration=args.duration,
            profiles={p.strip().upper() for p in args.profiles.split(",")},
            rps_a=max(0.1, args.rps_a),
            rps_b_concurrency=max(1, args.rps_b),
            interval_c=max(0.5, args.interval_c),
        )
    )
