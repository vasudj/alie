"""Shared data models used across gateway layers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class RiskResult:
    score: float
    flags: List[str] = field(default_factory=list)
    blocked: bool = False
    warned: bool = False
    primary_reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def verdict(self) -> str:
        if self.blocked:
            return "BLOCKED"
        if self.warned:
            return "WARNED"
        return "ALLOWED"
