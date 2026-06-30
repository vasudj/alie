"""
ALIE PoC — Unified Process Launcher
=====================================
Opens a dedicated terminal window for each service so logs don't mix.

Window layout
-------------
  Window 1  "ALIE — Bank Backend"    (port 3001)
  Window 2  "ALIE — API Gateway"     (port 3000, proxies → 3001)
  Window 3  "ALIE — Traffic Sim"     (profiles A/B/C → gateway:3000)

The launcher window itself stays open as the health-check / control plane.
Close it (or press Ctrl-C) to shut every child window down cleanly.

Usage
-----
  python run_all.py                          # all defaults
  python run_all.py --no-sim                 # backend + gateway only
  python run_all.py --profiles A,C           # skip DoS profile
  python run_all.py --sim-duration 120       # auto-stop sim after 2 min
  python run_all.py --gateway-port 3000 --backend-port 3001
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

HERE        = Path(__file__).resolve().parent       # alie/backend/
GATEWAY_DIR = HERE / "api_gateway"
SIM_SCRIPT  = HERE / "traffic_sim.py"
PYTHON      = sys.executable                        # absolute path, handles spaces

# ─────────────────────────────────────────────────────────────────────────────
# ANSI (launcher window only)
# ─────────────────────────────────────────────────────────────────────────────

BOLD  = "\033[1m"
DIM   = "\033[2m"
R     = "\033[0m"
GREEN = "\033[92m"
RED   = "\033[91m"
YEL   = "\033[93m"
CYAN  = "\033[96m"
BLUE  = "\033[94m"


def _tag(label: str, color: str) -> str:
    return f"{color}{BOLD}[{label:<12}]{R}"


TAG_BACK   = _tag("BACKEND",  BLUE)
TAG_GW     = _tag("GATEWAY",  CYAN)
TAG_SIM    = _tag("SIM",      GREEN)
TAG_LAUNCH = _tag("LAUNCHER", YEL)


def info(tag: str, msg: str) -> None: print(f"  {tag}  {msg}")
def warn(tag: str, msg: str) -> None: print(f"  {tag}  {YEL}{msg}{R}")
def err(tag: str,  msg: str) -> None: print(f"  {tag}  {RED}{msg}{R}")
def ok(tag: str,   msg: str) -> None: print(f"  {tag}  {GREEN}{msg}{R}")


# ─────────────────────────────────────────────────────────────────────────────
# New terminal window  (Windows-only, works on PowerShell and CMD)
# ─────────────────────────────────────────────────────────────────────────────

def _open_window(title: str, cmd: list[str], cwd: str, env: dict) -> subprocess.Popen:
    """
    Spawn `cmd` in a brand-new, titled console window on Windows.

    Strategy
    --------
    We use CREATE_NEW_CONSOLE so Windows opens a fresh window, then run
    either PowerShell or CMD inside it.

    PowerShell path  (preferred — colour output, Ctrl-C handling)
      Sets window title via $host.UI.RawUI.WindowTitle, then calls the
      service using PowerShell's call operator (&) which handles paths
      that contain spaces correctly.

    CMD fallback
      Uses `title` built-in then calls the service via a quoted string.

    The window stays open after the process exits (-NoExit / /k) so you
    can read crash output without the window disappearing instantly.
    """
    use_ps = shutil.which("powershell.exe") is not None

    if use_ps:
        # Build a PowerShell call expression.
        # & 'C:\path with spaces\python.exe' '-m' 'uvicorn' ...
        # Each token is single-quoted so spaces inside paths are safe.
        def _ps_quote(s: str) -> str:
            return "'" + s.replace("'", "''") + "'"

        call_expr = "& " + " ".join(_ps_quote(c) for c in cmd)
        # Set title, run service, keep window open on exit.
        ps_command = (
            f"$host.UI.RawUI.WindowTitle = {_ps_quote(title)}; "
            f"{call_expr}"
        )
        launch = [
            "powershell.exe",
            "-NoExit",
            "-Command", ps_command,
        ]
    else:
        # CMD fallback — quote tokens that contain spaces.
        def _cmd_quote(s: str) -> str:
            return f'"{s}"' if " " in s else s

        inner = " ".join(_cmd_quote(c) for c in cmd)
        launch = [
            "cmd.exe", "/k",
            f"title {title} && {inner}",
        ]

    return subprocess.Popen(
        launch,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        # KEY FLAG: tells Windows to open a brand-new console window.
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Health probe  (stdlib only — no httpx needed here)
# ─────────────────────────────────────────────────────────────────────────────

def _wait_for_http(url: str, tag: str, timeout: int = 45, interval: float = 1.5) -> bool:
    import urllib.request

    deadline = time.monotonic() + timeout
    attempt  = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status < 300:
                    ok(tag, f"Ready ✓  {url}  (attempt {attempt})")
                    return True
        except Exception:
            pass
        print(f"  {tag}  {DIM}Waiting… attempt {attempt}{R}", end="\r", flush=True)
        time.sleep(interval)

    print()   # clear the \r line
    err(tag, f"Did not respond within {timeout}s — {url}")
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Per-service window launchers
# ─────────────────────────────────────────────────────────────────────────────

def _launch_backend(port: int) -> subprocess.Popen:
    cmd = [
        PYTHON, "-m", "uvicorn",
        "app.main:app",
        "--host", "0.0.0.0",
        "--port", str(port),
        "--log-level", "info",
    ]
    env = {**os.environ, "PYTHONPATH": str(HERE)}
    info(TAG_BACK, f"Opening window → Bank Backend  ::{port}")
    return _open_window(
        title=f"ALIE — Bank Backend  :{port}",
        cmd=cmd,
        cwd=str(HERE),
        env=env,
    )


def _launch_gateway(gateway_port: int, backend_port: int) -> subprocess.Popen:
    backend_base = f"http://localhost:{backend_port}"
    routes_json = (
        f'{{'
        f'"/": "{backend_base}", '
        f'"/api": "{backend_base}", '
        f'"/api/v0": "{backend_base}", '
        f'"/api/v1": "{backend_base}", '
        f'"/api/v2": "{backend_base}", '
        f'"/api/admin": "{backend_base}", '
        f'"/api/internal": "{backend_base}", '
        f'"/api/beta": "{backend_base}", '
        f'"/.env": "{backend_base}", '
        f'"/api/graphql": "{backend_base}", '
        f'"/wp-admin": "{backend_base}", '
        f'"/actuator": "{backend_base}", '
        f'"/server-status": "{backend_base}"'
        f'}}'
    )
    cmd = [
        PYTHON, "-m", "uvicorn",
        "gateway.app:app",
        "--host", "0.0.0.0",
        "--port", str(gateway_port),
        "--log-level", "info",
    ]
    env = {
        **os.environ,
        "PYTHONPATH":       str(GATEWAY_DIR),
        "GATEWAY_PORT":     str(gateway_port),
        "BACKEND_PORT":     str(backend_port),
        "BACKEND_HOST":     "localhost",
        "BACKEND_BASE_URL": backend_base,
        "BACKEND_ROUTES":   routes_json,
    }
    info(TAG_GW, f"Opening window → API Gateway   ::{gateway_port}  (upstream: {backend_base})")
    return _open_window(
        title=f"ALIE — API Gateway  :{gateway_port}",
        cmd=cmd,
        cwd=str(GATEWAY_DIR),
        env=env,
    )


def _launch_simulator(gateway_port: int, profiles: str, duration: int) -> subprocess.Popen:
    gateway_url = f"http://localhost:{gateway_port}"
    cmd = [
        PYTHON, str(SIM_SCRIPT),
        "--url",      gateway_url,
        "--profiles", profiles,
    ]
    if duration > 0:
        cmd += ["--duration", str(duration)]

    env = {**os.environ, "PYTHONPATH": str(HERE)}
    info(TAG_SIM, f"Opening window → Traffic Sim   profiles={profiles} → {gateway_url}")
    return _open_window(
        title=f"ALIE — Traffic Simulator  [{profiles}]",
        cmd=cmd,
        cwd=str(HERE),
        env=env,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Shutdown
# ─────────────────────────────────────────────────────────────────────────────

_procs: list[tuple[str, subprocess.Popen]] = []


def _shutdown(signum=None, frame=None) -> None:
    print(f"\n\n{BOLD}{'─'*64}{R}")
    info(TAG_LAUNCH, "Ctrl-C — closing all terminal windows …")
    for name, proc in reversed(_procs):
        if proc.poll() is None:
            info(TAG_LAUNCH, f"  Terminating {name}  (pid={proc.pid})")
            try:
                proc.terminate()
            except OSError:
                pass
    time.sleep(1.5)
    for name, proc in _procs:
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
    ok(TAG_LAUNCH, "Done.")
    print(f"{BOLD}{'─'*64}{R}\n")
    sys.exit(0)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ALIE PoC — open separate terminal windows for each service"
    )
    parser.add_argument("--gateway-port",   default=3000, type=int,
                        help="Port for the API Gateway (default: 3000)")
    parser.add_argument("--backend-port",   default=3001, type=int,
                        help="Port for the Bank Backend (default: 3001)")
    parser.add_argument("--profiles",       default="A,B,C",
                        help="Traffic profiles A,B,C (default: A,B,C)")
    parser.add_argument("--sim-duration",   default=0, type=int,
                        help="Simulator duration in seconds; 0=infinite (default: 0)")
    parser.add_argument("--no-sim",         action="store_true",
                        help="Skip the traffic simulator window")
    parser.add_argument("--health-timeout", default=45, type=int,
                        help="Seconds to wait for each service health check (default: 45)")
    args = parser.parse_args()

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    shell_label = "PowerShell" if shutil.which("powershell.exe") else "CMD"

    print(f"\n{BOLD}{'═'*64}{R}")
    print(f"  {BOLD}ALIE PoC — Process Launcher{R}  (shell: {shell_label})")
    print(f"{'═'*64}")
    print(f"  Bank Backend  : http://localhost:{args.backend_port}")
    print(f"  API Gateway   : http://localhost:{args.gateway_port}")
    print(f"  Traffic Sim   : {'disabled' if args.no_sim else f'profiles={args.profiles}'}")
    print(f"{'═'*64}\n")

    # ── Window 1: Bank Backend ────────────────────────────────────────────────
    _procs.append(("BankBackend", _launch_backend(args.backend_port)))

    print()
    if not _wait_for_http(
        f"http://localhost:{args.backend_port}/api/health",
        TAG_BACK,
        timeout=args.health_timeout,
    ):
        err(TAG_LAUNCH, "Bank Backend did not start — check its terminal window for errors.")
        _shutdown()

    print()

    # ── Window 2: API Gateway ─────────────────────────────────────────────────
    _procs.append(("APIGateway", _launch_gateway(args.gateway_port, args.backend_port)))

    print()
    if not _wait_for_http(
        f"http://localhost:{args.gateway_port}/health",
        TAG_GW,
        timeout=args.health_timeout,
    ):
        warn(TAG_GW, "Gateway /health not responding yet — waiting 4 s and continuing anyway.")
        time.sleep(4)

    print()

    # ── Window 3: Traffic Simulator ───────────────────────────────────────────
    if not args.no_sim:
        info(TAG_SIM, "Pausing 2 s for gateway to finish startup …")
        time.sleep(2)
        _procs.append(("TrafficSim", _launch_simulator(args.gateway_port, args.profiles, args.sim_duration)))
        print()

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'─'*64}{R}")
    print(f"  {GREEN}{BOLD}All windows opened.{R}  "
          f"Press Ctrl-C here to close all of them.\n")
    print(f"  {'Service':<22}  {'Address'}")
    print(f"  {'─'*22}  {'─'*38}")
    print(f"  {'Bank Backend':<22}  http://localhost:{args.backend_port}")
    print(f"  {'  docs':<22}  http://localhost:{args.backend_port}/api/docs")
    print(f"  {'  zombie trap':<22}  "
          f"http://localhost:{args.backend_port}/api/v1/reports/legacy-ledger")
    print(f"  {'API Gateway':<22}  http://localhost:{args.gateway_port}")
    print(f"  {'  docs':<22}  http://localhost:{args.gateway_port}/docs")
    print(f"  {'  admin rules':<22}  "
          f"POST http://localhost:{args.gateway_port}/admin/rules")
    print(f"  {'  audit log':<22}  {HERE / 'scaled_down_audit.log'}")
    if not args.no_sim:
        print(f"  {'Traffic Simulator':<22}  "
              f"profiles={args.profiles} → gateway:{args.gateway_port}")
    print(f"{BOLD}{'─'*64}{R}\n")

    # ── Keep-alive: report if a window closes unexpectedly ────────────────────
    try:
        while True:
            time.sleep(3)
            for name, proc in _procs:
                if proc.poll() is not None:
                    warn(TAG_LAUNCH,
                         f"{name} window closed unexpectedly (rc={proc.poll()}).")
    except KeyboardInterrupt:
        _shutdown()


if __name__ == "__main__":
    main()
