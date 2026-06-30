"""Semgrep CLI runner — invokes semgrep as an async subprocess and processes results."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

from core.config import settings

log = structlog.get_logger(__name__)

# Where full JSON reports are persisted on disk
REPORTS_DIR = Path(__file__).resolve().parents[1] / "data" / "semgrep_reports"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


class SemgrepScanner:
    """Runs Semgrep scans as async subprocesses and manages report storage."""

    def __init__(self) -> None:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _default_target() -> str:
        """Return the default scan target — the banking backend app/ directory."""
        project_root = Path(__file__).resolve().parents[2]  # backend_alie-main/
        target = project_root / "app"
        if target.is_dir():
            return str(target)
        # Fallback to project root if app/ doesn't exist
        return str(project_root)

    async def run_scan(
        self,
        scan_id: Optional[str] = None,
        target_path: Optional[str] = None,
        config: str = "auto",
    ) -> Dict[str, Any]:
        """
        Execute a Semgrep scan and return structured results.

        Returns a dict with:
            scan_id, status, target_path, config, created_at, started_at,
            completed_at, findings_count, findings_by_severity, findings,
            error_message, report_path
        """
        scan_id = scan_id or str(uuid.uuid4())
        target = target_path or self._default_target()
        created_at = _now()

        log.info("semgrep_scan_starting", scan_id=scan_id, target=target, config=config)

        result: Dict[str, Any] = {
            "scan_id": scan_id,
            "status": "running",
            "target_path": target,
            "config": config,
            "created_at": created_at,
            "started_at": _now(),
            "completed_at": None,
            "findings_count": 0,
            "findings_critical": 0,
            "findings_high": 0,
            "findings_medium": 0,
            "findings_low": 0,
            "findings": [],
            "error_message": None,
            "report_path": None,
        }

        try:
            # Build semgrep command
            cmd = [
                "semgrep",
                "--json",
                "--config", config,
                "--no-git-ignore",       # scan everything
                "--timeout", "300",      # 5 min timeout per rule
                target,
            ]

            log.info("semgrep_cmd", cmd=" ".join(cmd))

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=600,  # 10 min total timeout
            )

            # Semgrep returns exit code 0 for success (even with findings),
            # exit code 1 for findings in --error mode, and other codes for errors
            raw_output = stdout.decode("utf-8", errors="replace")
            stderr_text = stderr.decode("utf-8", errors="replace")

            if proc.returncode not in (0, 1):
                result["status"] = "failed"
                result["error_message"] = f"Semgrep exited with code {proc.returncode}: {stderr_text[:2000]}"
                result["completed_at"] = _now()
                log.error("semgrep_scan_failed", scan_id=scan_id, exit_code=proc.returncode, stderr=stderr_text[:500])
                return result

            # Parse JSON output
            try:
                semgrep_output = json.loads(raw_output)
            except json.JSONDecodeError as e:
                result["status"] = "failed"
                result["error_message"] = f"Failed to parse Semgrep output: {e}"
                result["completed_at"] = _now()
                log.error("semgrep_parse_error", scan_id=scan_id, error=str(e))
                return result

            # Extract findings
            raw_findings = semgrep_output.get("results", [])
            findings = self._parse_findings(raw_findings)
            severity_counts = self._count_by_severity(findings)

            result["status"] = "completed"
            result["completed_at"] = _now()
            result["findings_count"] = len(findings)
            result["findings_critical"] = severity_counts.get("ERROR", 0)   # Semgrep uses ERROR for critical
            result["findings_high"] = severity_counts.get("WARNING", 0)
            result["findings_medium"] = severity_counts.get("INFO", 0)
            result["findings_low"] = severity_counts.get("INVENTORY", 0)
            result["findings"] = findings

            # Save full report to disk
            report_path = REPORTS_DIR / f"{scan_id}.json"
            report_data = {
                "scan_id": scan_id,
                "target_path": target,
                "config": config,
                "created_at": created_at,
                "completed_at": result["completed_at"],
                "semgrep_version": semgrep_output.get("version", "unknown"),
                "findings_count": len(findings),
                "severity_counts": severity_counts,
                "findings": findings,
                "errors": semgrep_output.get("errors", []),
                "paths": semgrep_output.get("paths", {}),
            }
            report_path.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")
            result["report_path"] = str(report_path)

            log.info(
                "semgrep_scan_completed",
                scan_id=scan_id,
                findings=len(findings),
                critical=result["findings_critical"],
                high=result["findings_high"],
                medium=result["findings_medium"],
                low=result["findings_low"],
            )

        except asyncio.TimeoutError:
            result["status"] = "failed"
            result["error_message"] = "Semgrep scan timed out after 600 seconds"
            result["completed_at"] = _now()
            log.error("semgrep_scan_timeout", scan_id=scan_id)

        except FileNotFoundError:
            result["status"] = "failed"
            result["error_message"] = (
                "Semgrep is not installed or not in PATH. "
                "Install with: pip install semgrep"
            )
            result["completed_at"] = _now()
            log.error("semgrep_not_found", scan_id=scan_id)

        except Exception as exc:
            result["status"] = "failed"
            result["error_message"] = f"Unexpected error: {str(exc)}"
            result["completed_at"] = _now()
            log.error("semgrep_scan_error", scan_id=scan_id, error=str(exc))

        return result

    @staticmethod
    def _parse_findings(raw_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract relevant fields from raw Semgrep results."""
        findings = []
        for r in raw_results:
            finding = {
                "rule_id": r.get("check_id", "unknown"),
                "severity": r.get("extra", {}).get("severity", "INFO"),
                "message": r.get("extra", {}).get("message", ""),
                "path": r.get("path", ""),
                "start_line": r.get("start", {}).get("line", 0),
                "end_line": r.get("end", {}).get("line", 0),
                "extra": {
                    "metadata": r.get("extra", {}).get("metadata", {}),
                    "lines": r.get("extra", {}).get("lines", ""),
                    "fix": r.get("extra", {}).get("fix", None),
                },
            }
            findings.append(finding)
        return findings

    @staticmethod
    def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def get_report(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Load a full JSON report from disk."""
        report_path = REPORTS_DIR / f"{scan_id}.json"
        if not report_path.exists():
            return None
        try:
            return json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            log.error("report_read_error", scan_id=scan_id, error=str(exc))
            return None
