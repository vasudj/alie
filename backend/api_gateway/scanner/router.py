"""REST API endpoints for triggering Semgrep scans and retrieving results."""

from __future__ import annotations

import asyncio
import uuid
from typing import Optional

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import JSONResponse

from core.config import settings
from db.db_helpers import (
    get_scan,
    get_scan_analysis,
    get_scans,
    store_scan,
    store_scan_analysis,
    update_scan_status,
)
from scanner.analyzer import ScanAnalyzer
from scanner.models import ScanRequest, ScanResponse
from scanner.semgrep_runner import SemgrepScanner
from scanner.websocket import broadcast_scan_update

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/scanner", tags=["scanner"])

# Shared scanner instance
_scanner = SemgrepScanner()


def _get_analyzer() -> ScanAnalyzer:
    """Get a ScanAnalyzer instance (internal Brain scoring, no external API needed)."""
    return ScanAnalyzer()


async def _run_scan_pipeline(scan_id: str, target_path: Optional[str], config: str) -> None:
    """
    Background task: run Semgrep scan → store results → run Brain analysis → store analysis.

    This is the core pipeline that wires everything together:
        Frontend trigger → Semgrep CLI → DB storage → Gemini AI → DB storage → WebSocket notify
    """
    try:
        # Step 1: Update status to running
        await update_scan_status(scan_id, "running")
        await broadcast_scan_update(scan_id, {"type": "scan_status", "status": "running"})

        # Step 2: Execute the Semgrep scan
        result = await _scanner.run_scan(
            scan_id=scan_id,
            target_path=target_path,
            config=config,
        )

        # Step 3: Store scan results in DB
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

        # Notify WebSocket subscribers
        await broadcast_scan_update(scan_id, {
            "type": "scan_completed",
            "status": result["status"],
            "findings_count": result.get("findings_count", 0),
        })

        log.info(
            "scan_pipeline_scan_done",
            scan_id=scan_id,
            status=result["status"],
            findings=result.get("findings_count", 0),
        )

        # Step 4: Run internal Brain analysis if scan succeeded
        if result["status"] == "completed":
            analyzer = _get_analyzer()
            if analyzer:
                await broadcast_scan_update(scan_id, {
                    "type": "analysis_status",
                    "status": "analyzing",
                })

                analysis = await analyzer.analyze_scan(
                    scan_id=scan_id,
                    findings=result["findings"],
                    target_path=result.get("target_path", ""),
                )

                # Step 5: Store analysis in DB
                await store_scan_analysis(scan_id, analysis)

                # Notify WebSocket
                await broadcast_scan_update(scan_id, {
                    "type": "analysis_ready",
                    "severity": analysis.get("severity_assessment", "UNKNOWN"),
                })

                log.info(
                    "scan_pipeline_analysis_done",
                    scan_id=scan_id,
                    severity=analysis.get("severity_assessment"),
                )
            else:
                log.info("scan_pipeline_no_analyzer", scan_id=scan_id, reason="no_gemini_key")

    except Exception as exc:
        log.error("scan_pipeline_error", scan_id=scan_id, error=str(exc))
        try:
            await update_scan_status(scan_id, "failed", error_message=str(exc))
            await broadcast_scan_update(scan_id, {
                "type": "scan_error",
                "error": str(exc),
            })
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────────────
# REST API Endpoints
# ──────────────────────────────────────────────────────────────────────


@router.post("/scan", response_model=ScanResponse, status_code=202)
async def trigger_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
) -> ScanResponse:
    """
    Trigger a new Semgrep scan.

    The scan runs asynchronously in the background. Use the returned scan_id
    to poll for status via GET /scanner/scans/{scan_id}.

    Future: connect via WebSocket at ws://host/ws/scanner and subscribe to
    the scan_id for real-time updates.
    """
    scan_id = str(uuid.uuid4())

    # Store initial scan record in DB
    await store_scan(
        scan_id=scan_id,
        target_path=request.target_path,
        config=request.config,
    )

    # Launch the scan pipeline in the background
    background_tasks.add_task(
        _run_scan_pipeline,
        scan_id=scan_id,
        target_path=request.target_path,
        config=request.config,
    )

    log.info("scan_triggered", scan_id=scan_id, config=request.config)

    return ScanResponse(
        scan_id=scan_id,
        status="queued",
        message="Semgrep scan queued. Poll GET /scanner/scans/{scan_id} for status.",
    )


@router.get("/scans")
async def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> JSONResponse:
    """List all scans with status, timestamps, and finding counts."""
    scans = await get_scans(limit=limit, offset=offset)
    return JSONResponse(content={
        "scans": scans,
        "total": len(scans),
        "limit": limit,
        "offset": offset,
    })


@router.get("/scans/{scan_id}")
async def get_scan_detail(scan_id: str) -> JSONResponse:
    """
    Get full details for a specific scan, including:
    - Scan metadata and finding counts
    - Brain AI analysis (if available)
    """
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    # Also try to get the brain analysis
    analysis = await get_scan_analysis(scan_id)

    return JSONResponse(content={
        "scan": scan,
        "brain_analysis": analysis,
    })


@router.get("/scans/{scan_id}/report")
async def get_scan_report(scan_id: str) -> JSONResponse:
    """
    Download the full raw Semgrep JSON report for a scan.

    This returns the complete semgrep output including all findings,
    metadata, errors, and scanned paths.
    """
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    report = _scanner.get_report(scan_id)
    if not report:
        if scan.get("status") in ("queued", "running"):
            raise HTTPException(status_code=202, detail="Scan is still in progress")
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    return JSONResponse(content=report)


@router.get("/scans/{scan_id}/analysis")
async def get_scan_brain_analysis(scan_id: str) -> JSONResponse:
    """
    Get only the Brain/Gemini AI analysis for a scan.

    Returns the severity assessment, categorized findings,
    remediation priorities, and executive summary.
    """
    analysis = await get_scan_analysis(scan_id)
    if not analysis:
        scan = await get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        if scan.get("status") in ("queued", "running"):
            raise HTTPException(status_code=202, detail="Scan still in progress, analysis not yet available")
        raise HTTPException(status_code=404, detail="No brain analysis available for this scan")

    return JSONResponse(content={"analysis": analysis})


@router.get("/health")
async def scanner_health() -> JSONResponse:
    """
    Health check for the scanner subsystem.

    Reports: semgrep availability, Gemini API status, reports directory.
    """
    health: dict = {"scanner": "operational"}

    # Check semgrep installation
    try:
        proc = await asyncio.create_subprocess_exec(
            "semgrep", "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        health["semgrep_version"] = stdout.decode().strip()
        health["semgrep_installed"] = True
    except (FileNotFoundError, asyncio.TimeoutError):
        health["semgrep_installed"] = False
        health["semgrep_version"] = None

    # Check Gemini analyzer
    analyzer = _get_analyzer()
    if analyzer:
        gemini_health = await analyzer.health_check()
        health["gemini"] = gemini_health
    else:
        health["gemini"] = {"status": "not_configured", "reason": "GEMINI_API_KEY not set"}

    # Reports directory
    from scanner.semgrep_runner import REPORTS_DIR
    health["reports_dir"] = str(REPORTS_DIR)
    health["reports_dir_exists"] = REPORTS_DIR.exists()

    return JSONResponse(content=health)
