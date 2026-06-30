"""Standalone CLI script to trigger a Semgrep scan for testing."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Ensure package imports work when running from scripts/
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanner.semgrep_runner import SemgrepScanner
from scanner.analyzer import ScanAnalyzer
from db.db_helpers import init_sqlite_storage, store_scan, update_scan_status, store_scan_analysis
from core.config import settings


async def main() -> None:
    print("=" * 60)
    print("  Semgrep Static Scan — CLI Runner")
    print("=" * 60)

    # Initialize DB
    print("\n[1/4] Initializing database...")
    await init_sqlite_storage()
    print("       Database ready.")

    # Run scan
    scanner = SemgrepScanner()
    scan_id = None

    import uuid
    scan_id = str(uuid.uuid4())
    print(f"\n[2/4] Starting Semgrep scan (scan_id: {scan_id})...")
    print(f"       Target: {scanner._default_target()}")

    await store_scan(scan_id=scan_id, target_path=None, config="auto")

    result = await scanner.run_scan(scan_id=scan_id)
    await update_scan_status(
        scan_id,
        result["status"],
        started_at=result.get("started_at"),
        completed_at=result.get("completed_at"),
        findings_count=result.get("findings_count", 0),
        findings_critical=result.get("findings_critical", 0),
        findings_high=result.get("findings_high", 0),
        findings_medium=result.get("findings_medium", 0),
        findings_low=result.get("findings_low", 0),
        error_message=result.get("error_message"),
        report_path=result.get("report_path"),
    )

    print(f"\n       Status: {result['status']}")
    print(f"       Findings: {result['findings_count']}")
    print(f"         Critical: {result['findings_critical']}")
    print(f"         High:     {result['findings_high']}")
    print(f"         Medium:   {result['findings_medium']}")
    print(f"         Low:      {result['findings_low']}")

    if result.get("error_message"):
        print(f"       Error: {result['error_message']}")
        return

    if result.get("report_path"):
        print(f"       Report: {result['report_path']}")

    # Run Brain analysis
    if result["status"] == "completed" and result.get("findings"):
        api_key = settings.GEMINI_API_KEY
        if api_key:
            print(f"\n[3/4] Running Brain/Gemini analysis on {len(result['findings'])} findings...")
            analyzer = ScanAnalyzer(api_key=api_key)
            analysis = await analyzer.analyze_scan(
                scan_id=scan_id,
                findings=result["findings"],
                target_path=result.get("target_path", ""),
            )
            await store_scan_analysis(scan_id, analysis)

            print(f"       Severity: {analysis.get('severity_assessment', 'N/A')}")
            print(f"\n       Summary:")
            summary = analysis.get("summary", "No summary available")
            for line in summary.split("\n"):
                print(f"         {line}")

            priorities = analysis.get("remediation_priorities", [])
            if priorities:
                print(f"\n       Remediation Priorities:")
                for p in priorities[:5]:
                    print(f"         • {p}")
        else:
            print("\n[3/4] Skipping Brain analysis (GEMINI_API_KEY not set)")
    else:
        print("\n[3/4] No findings to analyze")

    print(f"\n[4/4] Done! Scan {scan_id} complete.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
