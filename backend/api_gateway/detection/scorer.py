"""Risk scoring and threat classification for gateway requests."""

from __future__ import annotations

import asyncio
from typing import Dict, List, Tuple

from core.config import settings
from shared.models import RiskResult
from detection.rules import (
    rule_abnormal_frequency,
    rule_deprecated_endpoint,
    rule_debug_route,
    rule_high_error_rate,
    rule_internal_route,
    rule_missing_auth,
    rule_suspicious_user_agent,
    rule_undocumented_endpoint,
    rule_zombie_surface,
)


async def score_request(
    *,
    path: str,
    method: str,
    source_ip: str,
    headers: Dict[str, str],
    query_params: Dict[str, str],
) -> RiskResult:
    checks: List[Tuple[float, str]] = await asyncio.gather(
        rule_undocumented_endpoint(path),
        rule_deprecated_endpoint(path),
        rule_zombie_surface(path),
        rule_debug_route(path),
        rule_internal_route(path, source_ip, headers),
        rule_missing_auth(path, headers),
        rule_abnormal_frequency(source_ip),
        rule_high_error_rate(path),
        rule_suspicious_user_agent(headers),
    )

    flags = [label for score, label in checks if score > 0.0 and label]
    raw_score = sum(score for score, _ in checks)
    final_score = round(min(raw_score, 1.0), 4)
    primary_reason = flags[0] if flags else None

    return RiskResult(
        score=final_score,
        flags=flags,
        blocked=final_score >= settings.RISK_BLOCK_THRESHOLD,
        warned=final_score >= settings.RISK_WARN_THRESHOLD,
        primary_reason=primary_reason,
        details={
            "path": path,
            "method": method,
            "source_ip": source_ip,
            "query_params": query_params,
            "rule_scores": {label: sc for sc, label in checks if label},
        },
    )
