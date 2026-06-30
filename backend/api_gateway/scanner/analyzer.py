"""Internal Brain analyzer for Semgrep scan results (Internal Rules/Scoring Engine)."""

from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List

import structlog

log = structlog.get_logger(__name__)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


class ScanAnalyzer:
    """
    Analyzes Semgrep scan findings using Internal Brain Rules and Scoring.

    Provides categorization, severity assessment, and remediation priorities
    based on predefined heuristic rules and threat intelligence.
    """

    def __init__(self, api_key: str = "") -> None:
        # API key is ignored, kept for backward compatibility with router instantiation
        self.api_key = api_key

    async def analyze_scan(
        self,
        scan_id: str,
        findings: List[Dict[str, Any]],
        target_path: str = "",
    ) -> Dict[str, Any]:
        """
        Analyze Semgrep findings with our own Brain scoring system.
        """
        analysis_id = str(uuid.uuid4())
        created_at = _now()

        log.info("internal_scan_analysis_starting", scan_id=scan_id, findings_count=len(findings))

        if not findings:
            return {
                "id": analysis_id,
                "scan_id": scan_id,
                "created_at": created_at,
                "severity_assessment": "CLEAN",
                "categorized_findings": {},
                "remediation_priorities": [],
                "summary": "No security findings detected. The scanned codebase appears clean based on internal rules.",
                "raw_response": "Internal Heuristics: OK",
            }

        # Initialize categorizations
        cats = {"critical": [], "high": [], "medium": [], "low": []}
        score = 0

        # Score and categorize each finding
        for f in findings:
            sev = str(f.get("severity", "INFO")).upper()
            rule_id = f.get("rule_id", "unknown")
            msg = f.get("message", "")
            path = f"{f.get('path', '?')}:{f.get('start_line', 0)}"
            
            desc = f"[{rule_id}] {path} - {msg[:100]}..."

            if sev == "ERROR":
                cats["high"].append(desc)
                score += 10
            elif sev == "WARNING":
                cats["medium"].append(desc)
                score += 5
            else:
                cats["low"].append(desc)
                score += 1
                
            # Promote specific rules to critical
            if "hardcoded" in rule_id.lower() or "secret" in rule_id.lower() or "sqli" in rule_id.lower() or "injection" in rule_id.lower():
                if desc in cats["high"]: cats["high"].remove(desc)
                if desc in cats["medium"]: cats["medium"].remove(desc)
                if desc in cats["low"]: cats["low"].remove(desc)
                cats["critical"].append(desc)
                score += 20

        # Determine overall severity
        if len(cats["critical"]) > 0 or score > 50:
            severity = "CRITICAL"
        elif len(cats["high"]) > 0 or score > 20:
            severity = "HIGH"
        elif len(cats["medium"]) > 0 or score > 10:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Generate Remediation Priorities
        priorities = []
        if cats["critical"]:
            priorities.append(f"Priority 1: Immediately remediate {len(cats['critical'])} critical vulnerabilities (Secrets/Injections).")
        if cats["high"]:
            priorities.append(f"Priority 2: Address {len(cats['high'])} high severity bugs.")
        if cats["medium"]:
            priorities.append(f"Priority 3: Schedule fixes for {len(cats['medium'])} medium severity issues.")

        summary = f"Internal Brain analyzed {len(findings)} findings. Overall Risk Score: {score}. "
        summary += f"Found {len(cats['critical'])} critical, {len(cats['high'])} high, and {len(cats['medium'])} medium severity issues."

        result = {
            "id": analysis_id,
            "scan_id": scan_id,
            "created_at": created_at,
            "severity_assessment": severity,
            "categorized_findings": cats,
            "remediation_priorities": priorities,
            "summary": summary,
            "raw_response": f"Internal Score: {score}",
        }

        log.info(
            "internal_scan_analysis_completed",
            scan_id=scan_id,
            severity=severity,
            score=score
        )
        return result

    async def health_check(self) -> Dict[str, Any]:
        """Check status of internal analyzer."""
        return {
            "status": "healthy",
            "model": "internal-brain-heuristics",
            "response": "OK",
        }
