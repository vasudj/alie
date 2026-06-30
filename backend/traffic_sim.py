"""
backend_alie — Fake Traffic Simulator
Run: python traffic_sim.py [--url http://localhost:8000] [--mode sequential|random|burst|live]
"""

import requests
import time
import random
import argparse
import threading
import math
from datetime import datetime
from typing import Optional

# ─────────────────────────────────────────────
# ANSI colors
# ─────────────────────────────────────────────
R = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
DIM = "\033[2m"

TAG_COLORS = {
    "v2":       "\033[94m",   # blue
    "v1":       "\033[91m",   # red
    "admin":    "\033[93m",   # yellow
    "internal": "\033[92m",   # green
    "root":     "\033[95m",   # magenta
    "bait":     "\033[41;97m", # white on red bg — stands out as hacker traffic
}

METHOD_COLORS = {
    "GET":    "\033[94m",
    "POST":   "\033[93m",
    "PUT":    "\033[92m",
    "DELETE": "\033[91m",
}

# ─────────────────────────────────────────────
# Endpoint definitions
# ─────────────────────────────────────────────
def rand_str(n=6):
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=n))


def weighted_choice(items):
    """Pick one item from a list of dicts with `weight` key."""
    total = sum(max(0, i.get("weight", 1)) for i in items)
    if total <= 0:
       return random.choice(items)
    pick = random.uniform(0, total)
    upto = 0.0
    for item in items:
       upto += max(0, item.get("weight", 1))
       if upto >= pick:
          return item
    return items[-1]


DEFAULT_USERS = [
    {"email": "john.doe@example.com", "password": "password123"},
    {"email": "jane.smith@example.com", "password": "password123"},
    {"email": "bob.wilson@example.com", "password": "password123"},
]

DEFAULT_ADMIN = {"username": "admin@bank.local", "password": "admin_password_123"}
INTERNAL_API_KEY = "internal-service-token-xyz123-DO-NOT-EXPOSE"

ENDPOINTS = [
    # Root / debug
    dict(method="GET",  path="/",                               tag="root",     auth=False, weight=2),
    dict(method="GET",  path="/api/health",                     tag="root",     auth=False, weight=3),
    dict(method="GET",  path="/api/debug/routes",               tag="root",     auth=False, weight=1),
    dict(method="GET",  path="/api/debug/config",               tag="root",     auth=False, weight=1),
    dict(method="GET",  path="/api/v0/legacy-endpoint",         tag="root",     auth=False, weight=1),
    dict(method="GET",  path="/api/beta/experimental",          tag="root",     auth=False, weight=1),

    # v2 — secure
    dict(method="POST", path="/api/v2/auth/register",           tag="v2",       auth=False,
            weight=1,
         body=lambda: {"email": f"user_{rand_str()}@test.com", "full_name": "Test User",
                       "phone": "5551234567", "account_type": "savings"}),
    dict(method="POST", path="/api/v2/auth/login",              tag="v2",       auth=False,
        weight=6,
            body=lambda: random.choice(DEFAULT_USERS).copy()),
    dict(method="GET",  path="/api/v2/accounts/balance",        tag="v2",       auth=True,  weight=20),
    dict(method="GET",  path="/api/v2/transactions",            tag="v2",       auth=True,  weight=16),
    dict(method="GET",  path="/api/v2/health",                  tag="v2",       auth=False, weight=5),

    # v1 — legacy / vulnerable
    dict(method="POST", path="/api/v1/auth/login-legacy",       tag="v1",       auth=False,
        weight=5,
         params={"email": "admin@bank.local", "password": "admin123"}),
    dict(method="GET",  path="/api/v1/auth/check-email",        tag="v1",       auth=False,
        weight=4,
         params={"email": "test@example.com"}),
    dict(method="GET",  path="/api/v1/debug/user/1",            tag="v1",       auth=False, weight=3),
    dict(method="GET",  path="/api/v1/export/search",           tag="v1",       auth=False,
        weight=5,
            params={"query": "*"}),
    dict(method="POST", path="/api/v1/account/update",          tag="v1",       auth=False,
        weight=3,
            requires_account=True,
         body=lambda: {"balance": 99999, "is_admin": True}),
    dict(method="POST", path="/api/v1/user/update",             tag="v1",       auth=False,
        weight=3,
            requires_user=True,
         body=lambda: {"role": "admin", "is_admin": True}),
    dict(method="POST", path="/api/v1/quick-pay",               tag="v1",       auth=False,
        weight=8,
            requires_two_accounts=True,
         body=lambda: {"account_id": "acc_1", "recipient_id": "acc_2", "amount": 1000}),
    dict(method="GET",  path="/api/v1/internal/system/status",  tag="v1",       auth=False, weight=2),
    dict(method="GET",  path="/api/v1/internal/accounts/all",   tag="v1",       auth=False, weight=2),
    dict(method="GET",  path="/api/v1/legacy/error-test",       tag="v1",       auth=False, weight=1),
    dict(method="GET",  path="/api/v1/beta/quick-balance/1",    tag="v1",       auth=False, weight=2),

    # Admin
    dict(method="POST", path="/api/admin/login",                tag="admin",    auth=False,
        weight=4,
            send_as="params",
            params={"username": DEFAULT_ADMIN["username"], "password": DEFAULT_ADMIN["password"]}),
    dict(method="GET",  path="/api/admin/dashboard",            tag="admin",    auth=True, weight=6),
    dict(method="GET",  path="/api/admin/users/list",           tag="admin",    auth=True, weight=5),
    dict(method="GET",  path="/api/admin/db/query",             tag="admin",    auth=True,
        weight=2,
            params={"query_string": "SELECT * FROM users"}),
    dict(method="GET",  path="/api/admin/db/stats",             tag="admin",    auth=True, weight=3),
    dict(method="GET",  path="/api/admin/config/view",          tag="admin",    auth=True, weight=1),
    dict(method="GET",  path="/api/admin/audit/logs",           tag="admin",    auth=True, weight=2),
    dict(method="GET",  path="/api/admin/transactions/search",  tag="admin",    auth=True,
        weight=2,
         params={"q": "all"}),

    # Internal
    dict(method="POST", path="/api/internal/fraud/check-transaction", tag="internal", auth=False,
        weight=6,
            send_as="params",
            params={"account_id": "acc_1", "amount": 50000, "transaction_type": "transfer"}),
    dict(method="GET",  path="/api/internal/employees/list",          tag="internal", auth=False, weight=3),
    dict(method="GET",  path="/api/internal/employees/1/credentials", tag="internal", auth=False, weight=2),
    dict(method="GET",  path="/api/internal/reports/daily-summary",   tag="internal", auth=False, weight=3),
    dict(method="GET",  path="/api/internal/health/detailed",         tag="internal", auth=False, weight=4),
    dict(method="GET",  path="/api/internal/audit/recent-activities", tag="internal", auth=False, weight=2),

    # Bait / Honeypot — low weight, simulates occasional hacker probing (TrapNet)
    dict(method="GET",  path="/api/v1/admin/backup/db-dump",        tag="bait", auth=False, weight=0.4),
    dict(method="GET",  path="/api/v1/config/secrets",              tag="bait", auth=False, weight=0.3),
    dict(method="GET",  path="/api/v1/users/export_all",            tag="bait", auth=False, weight=0.4),
    dict(method="POST", path="/api/v1/auth/tokens/refresh-all",     tag="bait", auth=False, weight=0.2,
         body=lambda: {"scope": "all"}),
    dict(method="GET",  path="/api/v1/internal/ssh-keys",           tag="bait", auth=False, weight=0.3),
    dict(method="POST", path="/api/v1/payments/refund-override",    tag="bait", auth=False, weight=0.2,
         body=lambda: {"transaction_id": f"TXN-{rand_str(10)}", "amount": 9999}),
    dict(method="POST", path="/api/v1/debug/sql-console",           tag="bait", auth=False, weight=0.3,
         body=lambda: {"query": "SELECT * FROM users LIMIT 10"}),
    dict(method="POST", path="/api/v1/admin/impersonate",           tag="bait", auth=False, weight=0.2,
         body=lambda: {"user_id": random.randint(1, 100)}),
    dict(method="GET",  path="/.env",                               tag="bait", auth=False, weight=0.5),
    dict(method="POST", path="/api/graphql",                        tag="bait", auth=False, weight=0.3,
         body=lambda: {"query": "{__schema{types{name}}}"}),
    dict(method="GET",  path="/wp-admin/admin-ajax.php",            tag="bait", auth=False, weight=0.3),
    dict(method="GET",  path="/actuator/env",                       tag="bait", auth=False, weight=0.3),
    dict(method="GET",  path="/server-status",                      tag="bait", auth=False, weight=0.2),
]

# ─────────────────────────────────────────────
# Stats
# ─────────────────────────────────────────────
stats = {
    "total": 0,
    "ok": 0,
    "err": 0,
    "loops": 0,
    "per_tag": {"v2": 0, "v1": 0, "admin": 0, "internal": 0, "root": 0, "bait": 0},
    "p95_window_ms": [],
}
lock = threading.Lock()

def update_stats(status_code, tag, latency_ms):
    with lock:
        stats["total"] += 1
        stats["per_tag"][tag] = stats["per_tag"].get(tag, 0) + 1
        stats["p95_window_ms"].append(latency_ms)
        if len(stats["p95_window_ms"]) > 500:
            stats["p95_window_ms"] = stats["p95_window_ms"][-500:]
        if 200 <= status_code < 300:
            stats["ok"] += 1
        else:
            stats["err"] += 1

def status_color(code):
    if code == 0:
        return RED
    if 200 <= code < 300:
        return GREEN
    if 300 <= code < 400:
        return CYAN
    if 400 <= code < 500:
        return YELLOW
    return RED

def print_header(base_url, mode, delay, max_loops, token, users, rps, duration):
    print(f"\n{BOLD}{'-'*70}{R}")
    print(f"  {BOLD}backend_alie Traffic Simulator{R}")
    print(f"{'-'*70}")
    print(f"  Target  : {CYAN}{base_url}{R}")
    print(f"  Mode    : {BOLD}{mode}{R}")
    print(f"  Delay   : {delay}ms between requests (non-live modes)")
    print(f"  Users   : {users}")
    print(f"  Target RPS: {rps}")
    print(f"  Duration: {'infinite' if duration == 0 else str(duration) + 's'}")
    print(f"  Loops   : {'infinite' if max_loops == 0 else max_loops}")
    print(f"  Token   : {'set (yes)' if token else 'not set (auth endpoints will 401)'}")
    print(f"  Endpoints: {len(ENDPOINTS)}")
    print(f"{'-'*70}\n")
    print(f"  {'TIME':8}  {'M':4}  {'TAG':8}  {'PATH':42}  {'STATUS':6}  {'MS':>6}")
    print(f"  {'-'*8}  {'-'*4}  {'-'*8}  {'-'*42}  {'-'*6}  {'-'*6}")

def print_stats():
    pct = round(stats["ok"] / stats["total"] * 100) if stats["total"] > 0 else 0
    bar_len = 30
    filled = int(bar_len * pct / 100)
    bar = GREEN + "#" * filled + DIM + "-" * (bar_len - filled) + R
    with lock:
        p95 = 0
        if stats["p95_window_ms"]:
            ordered = sorted(stats["p95_window_ms"])
            idx = max(0, math.ceil(len(ordered) * 0.95) - 1)
            p95 = ordered[idx]
        tag_counts = " ".join(
            f"{k}:{v}" for k, v in stats["per_tag"].items() if v > 0
        )
    print(f"\n{'-'*70}")
    print(f"  Loop #{stats['loops']}  |  Total: {stats['total']}  |  {GREEN}OK: {stats['ok']}{R}  |  {RED}Err: {stats['err']}{R}  |  {bar} {pct}%")
    print(f"  p95(latency,last500): {p95}ms  |  Mix: {tag_counts if tag_counts else 'n/a'}")

# ─────────────────────────────────────────────
# Fire a single request
# ─────────────────────────────────────────────
def fire(ep: dict, base_url: str, token: Optional[str], session: requests.Session):
    headers = {"Content-Type": "application/json"}
    if token and ep.get("auth"):
        headers["Authorization"] = f"Bearer {token}"

    url = base_url.rstrip("/") + ep["path"]
    params = ep.get("params")
    body = ep["body"]() if callable(ep.get("body")) else None

    if ep.get("send_as") == "params" and body and not params:
        params = body
        body = None

    t0 = time.time()
    status = 0
    try:
        resp = session.request(
            method=ep["method"],
            url=url,
            headers=headers,
            params=params,
            json=body,
            timeout=8
        )
        status = resp.status_code
    except requests.exceptions.ConnectionError:
        status = 0
    except requests.exceptions.Timeout:
        status = 408
    except Exception:
        status = 0

    ms = int((time.time() - t0) * 1000)
    update_stats(status, ep["tag"], ms)

    now = datetime.now().strftime("%H:%M:%S")
    tag = ep["tag"]
    method = ep["method"]
    path = ep["path"]
    sc = str(status) if status != 0 else "ERR"

    tc = TAG_COLORS.get(tag, "")
    mc = METHOD_COLORS.get(method, "")
    stc = status_color(status)

    tag_str  = f"{tc}{tag:<8}{R}"
    meth_str = f"{mc}{method:<4}{R}"
    path_str = f"{path:<42}"
    stat_str = f"{stc}{sc:<6}{R}"
    ms_str   = f"{DIM}{ms:>5}ms{R}"

    print(f"  {DIM}{now}{R}  {meth_str}  {tag_str}  {path_str}  {stat_str}  {ms_str}")
    return status, resp if status != 0 else None


def discover_runtime_context(base_url: str):
    """Collect IDs used by endpoints so traffic looks like valid user actions."""
    context = {"user_ids": [], "account_ids": []}
    session = requests.Session()
    bootstrap_headers = {"x-zombie-bootstrap": "discovery"}

    try:
        users_resp = session.get(
            base_url.rstrip("/") + "/api/admin/users/list",
            headers=bootstrap_headers,
            timeout=4,
        )
        if users_resp.status_code == 200:
            payload = users_resp.json()
            context["user_ids"] = [u.get("id") for u in payload.get("users", []) if u.get("id")]
    except Exception:
        pass

    try:
        accounts_resp = session.get(
            base_url.rstrip("/") + "/api/v1/internal/accounts/all",
            headers={"api-key": INTERNAL_API_KEY, **bootstrap_headers},
            timeout=4,
        )
        if accounts_resp.status_code == 200:
            payload = accounts_resp.json()
            context["account_ids"] = [a.get("id") for a in payload.get("accounts", []) if a.get("id")]
    except Exception:
        pass

    return context


def apply_runtime_context(ep: dict, runtime_context: dict):
    """Inject discovered IDs into endpoints that need valid entities."""
    e = ep.copy()
    params = dict(e.get("params") or {})

    account_ids = runtime_context.get("account_ids", [])
    user_ids = runtime_context.get("user_ids", [])

    if e.get("requires_account") and account_ids:
        params["account_id"] = random.choice(account_ids)

    if e.get("requires_user") and user_ids:
        params["user_id"] = random.choice(user_ids)

    if e.get("requires_two_accounts") and len(account_ids) >= 2:
        src, dst = random.sample(account_ids, 2)

        def quick_pay_body():
            return {
                "account_id": src,
                "recipient_id": dst,
                "amount": random.choice([50, 80, 120, 250]),
                "description": "Live-like quick pay",
            }

        e["body"] = quick_pay_body

    if e["path"] == "/api/internal/fraud/check-transaction" and account_ids:
        params["account_id"] = random.choice(account_ids)

    if e["path"] == "/api/internal/reports/daily-summary":
        params["date"] = datetime.utcnow().strftime("%Y-%m-%d")

    if e["path"] == "/api/v1/beta/quick-balance/1" and account_ids:
        e["path"] = f"/api/v1/beta/quick-balance/{random.choice(account_ids)}"

    e["params"] = params if params else e.get("params")
    return e


def endpoint_has_required_context(ep: dict, runtime_context: dict):
    account_ids = runtime_context.get("account_ids", [])
    user_ids = runtime_context.get("user_ids", [])

    if ep.get("requires_account") and not account_ids:
        return False
    if ep.get("requires_user") and not user_ids:
        return False
    if ep.get("requires_two_accounts") and len(account_ids) < 2:
        return False
    return True


def choose_live_endpoint(eps, role, has_token):
    """Choose endpoint by role and auth state to approximate real user journeys."""
    weighted = []
    for ep in eps:
        w = ep.get("weight", 1)

        if role == "retail":
            if ep["tag"] == "v2":
                w *= 4
            elif ep["tag"] == "root":
                w *= 2
            elif ep["tag"] == "v1":
                w *= 1.4
            else:
                w *= 0.6
        elif role == "ops":
            if ep["tag"] == "admin":
                w *= 4
            elif ep["tag"] == "internal":
                w *= 3
            elif ep["tag"] == "v2":
                w *= 1.2
            else:
                w *= 0.8
        else:
            if ep["tag"] == "v1":
                w *= 2.5
            elif ep["tag"] == "internal":
                w *= 1.8
            elif ep["tag"] == "v2":
                w *= 1.4

        if ep.get("auth") and not has_token:
            w *= 0.25
        if ep["path"].endswith("/auth/login") and has_token:
            w *= 0.2

        e = ep.copy()
        e["weight"] = w
        weighted.append(e)

    return weighted_choice(weighted)


def try_login_v2(base_url, session, user):
    login_ep = {
        "method": "POST",
        "path": "/api/v2/auth/login",
        "tag": "v2",
        "auth": False,
        "body": lambda: {"email": user["email"], "password": user["password"]},
    }
    status, resp = fire(login_ep, base_url, None, session)
    if status == 200 and resp is not None:
        try:
            payload = resp.json()
            return payload.get("access_token")
        except Exception:
            return None
    return None


def live_worker(worker_id, eps, base_url, stop_event, seed_token, target_rps, jitter, session_requests, runtime_context):
    random.seed(time.time() + worker_id)
    session = requests.Session()
    role = weighted_choice([
        {"role": "retail", "weight": 70},
        {"role": "legacy", "weight": 20},
        {"role": "ops", "weight": 10},
    ])["role"]

    token = seed_token or None
    reqs_with_token = 0
    user = random.choice(DEFAULT_USERS)
    login_retry_after = 0.0
    login_failures = 0

    if role != "ops" and not token:
        token = try_login_v2(base_url, session, user)
        if not token:
            login_failures += 1
            login_retry_after = time.time() + min(10, 2 ** login_failures)

    base_interval = max(0.01, 1.0 / max(0.1, target_rps))

    while not stop_event.is_set():
        if role != "ops" and (not token or reqs_with_token >= session_requests):
            if time.time() < login_retry_after:
                time.sleep(0.2)
                continue
            user = random.choice(DEFAULT_USERS)
            token = try_login_v2(base_url, session, user)
            reqs_with_token = 0
            if token:
                login_failures = 0
            else:
                login_failures += 1
                login_retry_after = time.time() + min(12, 2 ** login_failures)
                continue

        ep = choose_live_endpoint(eps, role, has_token=bool(token or seed_token))
        if not endpoint_has_required_context(ep, runtime_context):
            continue
        ep = apply_runtime_context(ep, runtime_context)
        effective_token = seed_token or token
        fire(ep, base_url, effective_token, session)

        if ep.get("auth") and effective_token:
            reqs_with_token += 1

        # Simulate real traffic variance with burst cycles and random jitter.
        cycle = 45.0
        phase = (time.time() % cycle) / cycle
        wave = 0.75 + (0.65 * math.sin(phase * 2 * math.pi))
        wave = max(0.25, wave)
        sleep_s = (base_interval / wave) * random.uniform(max(0.05, 1 - jitter), 1 + jitter)
        time.sleep(max(0.01, sleep_s))

# ─────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────
def run(base_url, mode, delay_ms, max_loops, token, tags, users, rps, duration, jitter, session_requests):
    session = requests.Session()
    eps = [e for e in ENDPOINTS if e["tag"] in tags]
    if not eps:
        print(f"{RED}No endpoints selected. Check --tags.{R}")
        return

    print_header(base_url, mode, delay_ms, max_loops, token, users, rps, duration)

    if mode == "live":
        runtime_context = discover_runtime_context(base_url)
        stop_event = threading.Event()
        threads = []
        start_ts = time.time()
        worker_rps = max(0.1, rps / max(1, users))

        for idx in range(users):
            t = threading.Thread(
                target=live_worker,
                args=(idx, eps, base_url, stop_event, token, worker_rps, jitter, session_requests, runtime_context),
                daemon=True,
            )
            threads.append(t)
            t.start()

        loop = 0
        try:
            while True:
                loop += 1
                stats["loops"] = loop
                time.sleep(2)
                print_stats()

                if duration > 0 and (time.time() - start_ts) >= duration:
                    print(f"\n  {GREEN}Live run completed ({duration}s).{R}\n")
                    break

                if max_loops > 0 and loop >= max_loops:
                    print(f"\n  {GREEN}Done — {loop} stats window loop(s) completed.{R}\n")
                    break
        except KeyboardInterrupt:
            print(f"\n\n  {YELLOW}Stopped by user.{R}")
        finally:
            stop_event.set()
            for t in threads:
                t.join(timeout=1)
            print_stats()
            print()
        return

    loop = 0
    try:
        while True:
            loop += 1
            stats["loops"] = loop

            batch = eps if mode != "random" else random.sample(eps, len(eps))

            if mode == "burst":
                threads = []
                for ep in batch:
                    t = threading.Thread(target=fire, args=(ep, base_url, token, session), daemon=True)
                    threads.append(t)
                    t.start()
                for t in threads:
                    t.join()
            else:
                for ep in batch:
                    fire(ep, base_url, token, session)
                    time.sleep(delay_ms / 1000)

            print_stats()

            if max_loops > 0 and loop >= max_loops:
                print(f"\n  {GREEN}Done — {loop} loop(s) completed.{R}\n")
                break

            time.sleep(delay_ms / 1000)

    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}Stopped by user.{R}")
        print_stats()
        print()

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="backend_alie fake traffic simulator")
    parser.add_argument("--url",    default="http://localhost:8000", help="Base URL of the app")
    parser.add_argument("--mode",   default="live", choices=["sequential", "random", "burst", "live"],
                        help="sequential = one by one, random = shuffled, burst = all parallel, live = weighted virtual users")
    parser.add_argument("--delay",  default=600, type=int, help="Delay in ms between requests (sequential/random)")
    parser.add_argument("--loops",  default=0,   type=int, help="Number of loops (0 = infinite). In live mode, loops are stats windows")
    parser.add_argument("--token",  default="",            help="Bearer token for authenticated endpoints")
    parser.add_argument("--tags",   default="v2,v1,admin,internal,root,bait",
                        help="Comma-separated tags to include: v2,v1,admin,internal,root,bait")
    parser.add_argument("--users",  default=18,  type=int, help="Virtual users for live mode")
    parser.add_argument("--rps",    default=14.0, type=float, help="Approx total target requests/sec in live mode")
    parser.add_argument("--duration", default=0, type=int, help="Duration in seconds for live mode (0 = infinite)")
    parser.add_argument("--jitter", default=0.35, type=float, help="Traffic jitter factor for live mode")
    parser.add_argument("--session-requests", default=7, type=int, help="Auth requests per session before re-login")
    args = parser.parse_args()

    run(
        base_url=args.url,
        mode=args.mode,
        delay_ms=args.delay,
        max_loops=args.loops,
        token=args.token,
        tags=set(args.tags.split(",")),
        users=max(1, args.users),
        rps=max(0.1, args.rps),
        duration=max(0, args.duration),
        jitter=max(0.0, min(args.jitter, 0.95)),
        session_requests=max(1, args.session_requests),
    )
