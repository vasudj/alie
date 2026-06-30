"""Detection rules for zombie/shadow API scoring."""

from __future__ import annotations

from typing import Dict, Tuple

from core.config import settings
from eventbus.redis_bus import get_error_rate, increment_request_count


async def rule_undocumented_endpoint(path: str) -> Tuple[float, str]:
    if path == "/":
        return 0.0, ""
    documented = settings.documented_prefixes()
    if not any(path.startswith(p) for p in documented):
        return 0.35, "undocumented_endpoint"
    return 0.0, ""


async def rule_deprecated_endpoint(path: str) -> Tuple[float, str]:
    if any(dep in path for dep in settings.deprecated_paths()):
        return 0.45, "deprecated_endpoint"
    return 0.0, ""


async def rule_zombie_surface(path: str) -> Tuple[float, str]:
    markers = ["/legacy/", "/api/v0/", "/api/v1/beta/", "/api/beta/", "/api/debug/", "/debug/", "/old/", "/deprecated/"]
    if any(marker in path for marker in markers):
        return 0.40, "zombie_surface"
    return 0.0, ""


async def rule_debug_route(path: str) -> Tuple[float, str]:
    debug = settings.debug_paths()
    if any(path.startswith(d) or path == d for d in debug):
        return 0.55, "debug_route_access"
    return 0.0, ""


async def rule_internal_route(path: str, source_ip: str, headers: Dict[str, str]) -> Tuple[float, str]:
    del source_ip
    if any(path.startswith(i) for i in settings.internal_paths()):
        s2s_token = headers.get("x-service-token", "")
        bootstrap = headers.get("x-zombie-bootstrap", "")
        if not s2s_token and not bootstrap:
            return 0.50, "internal_route_no_service_token"
        return 0.15, "internal_route_with_token"
    return 0.0, ""


async def rule_missing_auth(path: str, headers: Dict[str, str]) -> Tuple[float, str]:
    needs_auth = any(path.startswith(p) for p in settings.auth_required_prefixes())
    if needs_auth:
        has_auth = bool(
            headers.get("authorization")
            or headers.get("x-api-key")
            or headers.get("api-key")
            or headers.get("x-access-token")
            or headers.get("x-service-token")
            or headers.get("x-zombie-bootstrap")
        )
        if not has_auth:
            return 0.40, "missing_auth"
    return 0.0, ""


async def rule_abnormal_frequency(source_ip: str) -> Tuple[float, str]:
    count = await increment_request_count(source_ip)
    max_req = settings.RATE_MAX_REQUESTS
    if count > max_req * 3:
        return 0.60, f"abnormal_frequency:{count}_reqs_in_window"
    if count > max_req:
        ratio = min((count - max_req) / max_req, 1.0)
        return 0.20 + 0.20 * ratio, f"elevated_frequency:{count}_reqs_in_window"
    return 0.0, ""


async def rule_high_error_rate(path: str) -> Tuple[float, str]:
    rate = await get_error_rate(path)
    threshold = settings.ERROR_RATE_THRESHOLD
    if rate >= threshold:
        return 0.45, f"high_error_rate:{rate:.0%}"
    if rate >= threshold * 0.6:
        return 0.20, f"elevated_error_rate:{rate:.0%}"
    return 0.0, ""


async def rule_suspicious_user_agent(headers: Dict[str, str]) -> Tuple[float, str]:
    ua = headers.get("user-agent", "").lower()
    suspicious_ua = [
        "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
        "gobuster", "ffuf", "wfuzz", "burpsuite", "zaproxy",
        "nuclei", "metasploit", "python-requests/2.1",
    ]
    for bad_ua in suspicious_ua:
        if bad_ua in ua:
            return 0.65, f"suspicious_user_agent:{bad_ua}"
    if ua == "" or ua == "-":
        return 0.20, "missing_user_agent"
    return 0.0, ""
