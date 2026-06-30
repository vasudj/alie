"""Pydantic models for Semgrep scan requests, responses, and analysis results."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Request body to trigger a new Semgrep scan."""
    target_path: Optional[str] = Field(
        None,
        description="Override the default scan target directory. "
                    "If not provided, scans the project's own source code.",
    )
    config: str = Field(
        "auto",
        description="Semgrep config/ruleset to use (e.g., 'auto', 'p/python', 'p/owasp-top-ten').",
    )


class ScanResponse(BaseModel):
    """Response returned immediately after triggering a scan."""
    scan_id: str
    status: str = "queued"
    message: str = "Scan queued successfully"


class ScanFinding(BaseModel):
    """A single Semgrep finding."""
    rule_id: str
    severity: str
    message: str
    path: str
    start_line: int
    end_line: int
    extra: Dict[str, Any] = Field(default_factory=dict)


class ScanResultSummary(BaseModel):
    """Summary of a completed scan (stored in DB, returned via API)."""
    scan_id: str
    status: str
    target_path: Optional[str] = None
    config: str = "auto"
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    findings_count: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    error_message: Optional[str] = None
    report_path: Optional[str] = None


class ScanDetail(BaseModel):
    """Full scan detail including findings and optional brain analysis."""
    scan: ScanResultSummary
    findings: List[ScanFinding] = Field(default_factory=list)
    brain_analysis: Optional[ScanAnalysisResult] = None


class ScanAnalysisResult(BaseModel):
    """Brain/Gemini AI analysis of a Semgrep scan."""
    scan_id: str
    created_at: str
    severity_assessment: str = ""
    categorized_findings: Dict[str, Any] = Field(default_factory=dict)
    remediation_priorities: List[str] = Field(default_factory=list)
    summary: str = ""


# Fix forward reference in ScanDetail
ScanDetail.model_rebuild()


class ScanListResponse(BaseModel):
    """Response for listing all scans."""
    scans: List[ScanResultSummary]
    total: int
