"""
ALIE — Level 3 Policy Orchestrator  (The Decommissioner)
=========================================================
Part 4 of the ALIE 5-part security pipeline.

This service is the governance layer.  It does NOT block active attackers
(that is Level 2's job).  It looks for *architectural* rot — Zombie APIs,
orphaned endpoints, public surfaces with no owner — and executes a
structured decommissioning playbook for each one.

Pipeline position
-----------------
  [Gateway :8000]  →  [Risk Engine :8002]  →  [Rules Engine :8003]
                                           →  [Policy Orchestrator :8004]  ← YOU ARE HERE

Playbook (3 steps per offending endpoint)
-----------------------------------------
  A  Mock Jira ticket      — structured JSON alert with ghost-client list
                             and successor migration advice.
  B  Mock Slack webhook    — SOC team notification that sunset has started.
  C  Gateway soft-shield   — live HTTP POST to /admin/rules on the gateway
                             (Deprecation header injection OR 5 % Brownout,
                             chosen by a weighted coin-flip per endpoint).

Upstream contracts
------------------
  Risk Engine  GET  http://127.0.0.1:8002/api/v1/risk-scores
               Response shape → see §2 (RiskScoreResponse pydantic models).
  Gateway      POST http://127.0.0.1:8000/admin/rules
               Body → {"type": "Brownout"|"Deprecation", "target": "<path>"}

Run:
    python level3_policy_orchestrator.py [--port 8004]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ─────────────────────────────────────────────────────────────────────────────
# §0  Configuration
# ─────────────────────────────────────────────────────────────────────────────

RISK_ENGINE_URL  = "http://127.0.0.1:8002/api/v1/risk-scores"
GATEWAY_RULES_URL = "http://127.0.0.1:8000/admin/rules"

POLL_INTERVAL_S      = 10       # seconds between risk-engine polls
LIFECYCLE_RISK_FLOOR = 80.0     # trigger threshold (lifecycle_risk score)
HTTP_TIMEOUT_S       = 5.0      # timeout for outbound calls

# Mock ghost-client pools: IPs that were last seen calling the zombie endpoint.
# In production these would come from a SIEM or the gateway's access logs.
_GHOST_CLIENT_POOL = [
    "10.0.1.45", "10.0.1.88", "10.0.2.17", "10.0.2.99",
    "10.0.3.212", "172.16.4.5", "192.168.100.22",
]

# Successor mapping: legacy path → recommended modern replacement.
_SUCCESSOR_MAP: Dict[str, str] = {
    "/bank/api/v1/reports/legacy-ledger":
        "Migrate callers to /bank/api/v2/reports/ledger "
        "(paginated, authenticated, <10 KB per page). "
        "Traffic patterns indicate batch clients can adopt the v2 streaming endpoint.",
    "/api/v1/":
        "Replace with /api/v2/ equivalents. "
        "All v1 functionality has a v2 counterpart; see the OpenAPI migration guide.",
}
_DEFAULT_SUCCESSOR = (
    "Review API catalogue for a v2 equivalent. "
    "If no replacement exists, schedule a Product review before sunset."
)


# ─────────────────────────────────────────────────────────────────────────────
# §1  Workflow State
# ─────────────────────────────────────────────────────────────────────────────

class PlaybookStep(str, Enum):
    JIRA_TICKET  = "jira_ticket"
    SLACK_ALERT  = "slack_alert"
    GATEWAY_RULE = "gateway_rule"


class StepStatus(str, Enum):
    PENDING  = "pending"
    DONE     = "done"
    FAILED   = "failed"
    SKIPPED  = "skipped"


class StepRecord(BaseModel):
    step:        PlaybookStep
    status:      StepStatus = StepStatus.PENDING
    completed_at: Optional[str] = None
    detail:      Optional[str]  = None
    payload:     Optional[Dict[str, Any]] = None


class GatewayAction(str, Enum):
    DEPRECATION = "Deprecation"
    BROWNOUT    = "Brownout"


class WorkflowRecord(BaseModel):
    workflow_id:       str
    path:              str
    triggered_at:      str
    trigger_reason:    str
    lifecycle_risk:    float
    composite_score:   float
    risk_tier:         str
    ghost_clients:     List[str]
    successor_advice:  str
    gateway_action:    GatewayAction
    steps:             Dict[PlaybookStep, StepRecord] = Field(default_factory=dict)
    completed_at:      Optional[str] = None
    overall_status:    str = "running"   # running | completed | partial_failure


# Keyed by endpoint path.  Once an entry exists, the playbook will not re-fire.
_active_workflows: Dict[str, WorkflowRecord] = {}
# Paths whose playbook has finished (success or partial).  Never re-triggered.
_completed_paths: set[str] = set()
# Global asyncio lock protecting both dicts.
_workflow_lock = asyncio.Lock()


# ─────────────────────────────────────────────────────────────────────────────
# §2  Upstream response models (subset — only fields we consume)
# ─────────────────────────────────────────────────────────────────────────────

class _LifecycleSnap(BaseModel):
    lifecycle_risk:    float = 0.0
    confidence_pct:    float = 0.0
    lifecycle_weighted: float = 0.0


class _MLSnap(BaseModel):
    ml_probability_factor: float = 0.0
    ml_score:              float = 0.0
    signals_fired:         List[str] = Field(default_factory=list)


class _CompositeSnap(BaseModel):
    composite_risk_score: float = 0.0
    risk_tier:            str   = "MINIMAL"
    recommended_action:   str   = ""


class _EndpointResult(BaseModel):
    path:      str
    lifecycle: _LifecycleSnap  = Field(default_factory=_LifecycleSnap)
    ml:        _MLSnap         = Field(default_factory=_MLSnap)
    composite: _CompositeSnap  = Field(default_factory=_CompositeSnap)
    flags:     List[str]       = Field(default_factory=list)


class _RiskScoreResponse(BaseModel):
    results: List[_EndpointResult] = Field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# §3  Step A — Mock Jira Ticket
# ─────────────────────────────────────────────────────────────────────────────

async def _step_jira(wf: WorkflowRecord) -> StepRecord:
    """Simulate creating a Jira ticket by emitting a structured JSON log."""

    ticket_id = f"ALIE-{random.randint(1000, 9999)}"
    payload = {
        "ticket_id":        ticket_id,
        "ticket_type":      "Automated API Sunset",
        "project":          "ALIE-DECOM",
        "priority":         "High" if wf.lifecycle_risk >= 80 else "Medium",
        "target_api":       wf.path,
        "ghost_clients":    wf.ghost_clients,
        "lifecycle_risk":   wf.lifecycle_risk,
        "composite_score":  wf.composite_score,
        "risk_tier":        wf.risk_tier,
        "successor_advice": wf.successor_advice,
        "labels":           ["zombie-api", "automated-sunset", "alie-l3"],
        "description": (
            f"The ALIE Policy Orchestrator has identified `{wf.path}` as a "
            f"Zombie/High-Risk API (lifecycle_risk={wf.lifecycle_risk}, "
            f"composite={wf.composite_score}).\n\n"
            f"Ghost clients still active: {wf.ghost_clients}\n\n"
            f"Recommended next steps:\n"
            f"1. Notify ghost client teams ({', '.join(wf.ghost_clients)}) "
            f"to migrate within 30 days.\n"
            f"2. {wf.successor_advice}\n"
            f"3. Schedule hard shutdown after migration window expires.\n"
            f"4. Confirm removal from API catalogue and OpenAPI spec."
        ),
        "created_at":   datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "created_by":   "alie-policy-orchestrator/auto",
        "workflow_id":  wf.workflow_id,
    }

    print(
        f"\n{'─'*70}\n"
        f"  [L3 STEP A — JIRA]  Workflow {wf.workflow_id}\n"
        f"{'─'*70}\n"
        f"{json.dumps(payload, indent=2)}\n"
    )

    return StepRecord(
        step=PlaybookStep.JIRA_TICKET,
        status=StepStatus.DONE,
        completed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        detail=f"Ticket {ticket_id} created (mocked).",
        payload=payload,
    )


# ─────────────────────────────────────────────────────────────────────────────
# §4  Step B — Mock Slack SOC Alert
# ─────────────────────────────────────────────────────────────────────────────

async def _step_slack(wf: WorkflowRecord) -> StepRecord:
    """Simulate posting a Slack message to the SOC channel."""

    action_str = (
        "🌑 Brownout (5 % traffic drop)"
        if wf.gateway_action == GatewayAction.BROWNOUT
        else "⚠️  Deprecation headers injected"
    )
    payload = {
        "webhook_target":  "#soc-api-governance",
        "username":        "ALIE Policy Bot",
        "icon_emoji":      ":skull_and_crossbones:",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Zombie API Decommission Started — {wf.risk_tier}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*API Path:*\n`{wf.path}`"},
                    {"type": "mrkdwn", "text": f"*Risk Tier:*\n{wf.risk_tier}"},
                    {"type": "mrkdwn", "text": f"*Lifecycle Risk:*\n{wf.lifecycle_risk}/100"},
                    {"type": "mrkdwn", "text": f"*Composite Score:*\n{wf.composite_score}/100"},
                    {"type": "mrkdwn", "text": f"*Ghost Clients:*\n{', '.join(wf.ghost_clients)}"},
                    {"type": "mrkdwn", "text": f"*Gateway Action:*\n{action_str}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Successor Advice:*\n{wf.successor_advice}\n\n"
                        f"*Trigger:* {wf.trigger_reason}\n"
                        f"*Workflow ID:* `{wf.workflow_id}`"
                    ),
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Jira Ticket"},
                        "url":  "https://jira.internal/browse/ALIE",
                        "style": "danger",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Override / Rollback"},
                        "url":  f"http://127.0.0.1:8004/api/v1/workflows/{wf.workflow_id}/rollback",
                    },
                ],
            },
        ],
        "sent_at":      datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "workflow_id":  wf.workflow_id,
    }

    print(
        f"\n{'─'*70}\n"
        f"  [L3 STEP B — SLACK]  Workflow {wf.workflow_id}\n"
        f"{'─'*70}\n"
        f"{json.dumps(payload, indent=2)}\n"
    )

    return StepRecord(
        step=PlaybookStep.SLACK_ALERT,
        status=StepStatus.DONE,
        completed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        detail="SOC Slack alert dispatched to #soc-api-governance (mocked).",
        payload=payload,
    )


# ─────────────────────────────────────────────────────────────────────────────
# §5  Step C — Gateway Soft-Shield  (live HTTP)
# ─────────────────────────────────────────────────────────────────────────────

async def _step_gateway(wf: WorkflowRecord) -> StepRecord:
    """Send an actual HTTP POST to the API Gateway's /admin/rules endpoint."""

    rule_payload = {
        "type":   wf.gateway_action.value,   # "Deprecation" or "Brownout"
        "target": wf.path,
        "meta": {
            "workflow_id":   wf.workflow_id,
            "reason":        "alie-l3-automated-sunset",
            "lifecycle_risk": wf.lifecycle_risk,
            "composite_score": wf.composite_score,
            "applied_at":    datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
    }

    print(
        f"\n{'─'*70}\n"
        f"  [L3 STEP C — GATEWAY]  Workflow {wf.workflow_id}\n"
        f"{'─'*70}\n"
        f"  POST {GATEWAY_RULES_URL}\n"
        f"  Body: {json.dumps(rule_payload)}\n"
    )

    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S) as client:
            resp = await client.post(GATEWAY_RULES_URL, json=rule_payload)
            resp.raise_for_status()
            body = resp.json()
            rule_id = body.get("rule_id", "unknown")
            detail = (
                f"Gateway accepted rule. "
                f"action={wf.gateway_action.value}  rule_id={rule_id}  "
                f"status={resp.status_code}"
            )
            print(f"  ✓ Gateway response [{resp.status_code}]: {body}\n")
            return StepRecord(
                step=PlaybookStep.GATEWAY_RULE,
                status=StepStatus.DONE,
                completed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                detail=detail,
                payload={**rule_payload, "gateway_response": body},
            )

    except httpx.ConnectError:
        msg = f"Gateway unreachable at {GATEWAY_RULES_URL} — rule queued for retry."
        print(f"  ✗ {msg}\n")
        return StepRecord(
            step=PlaybookStep.GATEWAY_RULE,
            status=StepStatus.FAILED,
            completed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            detail=msg,
            payload=rule_payload,
        )

    except httpx.HTTPStatusError as exc:
        msg = f"Gateway rejected rule: HTTP {exc.response.status_code} — {exc.response.text}"
        print(f"  ✗ {msg}\n")
        return StepRecord(
            step=PlaybookStep.GATEWAY_RULE,
            status=StepStatus.FAILED,
            completed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            detail=msg,
            payload=rule_payload,
        )

    except Exception as exc:
        msg = f"Unexpected error contacting gateway: {exc}"
        print(f"  ✗ {msg}\n")
        return StepRecord(
            step=PlaybookStep.GATEWAY_RULE,
            status=StepStatus.FAILED,
            completed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            detail=msg,
            payload=rule_payload,
        )


# ─────────────────────────────────────────────────────────────────────────────
# §6  Decommissioning Playbook Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def _build_workflow(path: str, result: _EndpointResult, trigger_reason: str) -> WorkflowRecord:
    """Construct an initial WorkflowRecord from the risk engine data."""
    ghost_clients = random.sample(_GHOST_CLIENT_POOL, k=min(3, len(_GHOST_CLIENT_POOL)))

    successor = _DEFAULT_SUCCESSOR
    for prefix, advice in _SUCCESSOR_MAP.items():
        if path.startswith(prefix):
            successor = advice
            break

    # Weighted coin-flip: Brownout for very high risk, Deprecation otherwise.
    # For composite ≥ 90 we escalate straight to Brownout.
    gateway_action = (
        GatewayAction.BROWNOUT
        if result.composite.composite_risk_score >= 90 or random.random() < 0.5
        else GatewayAction.DEPRECATION
    )

    return WorkflowRecord(
        workflow_id=f"WF-{uuid.uuid4().hex[:10].upper()}",
        path=path,
        triggered_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        trigger_reason=trigger_reason,
        lifecycle_risk=result.lifecycle.lifecycle_risk,
        composite_score=result.composite.composite_risk_score,
        risk_tier=result.composite.risk_tier,
        ghost_clients=ghost_clients,
        successor_advice=successor,
        gateway_action=gateway_action,
        steps={step: StepRecord(step=step) for step in PlaybookStep},
    )


async def execute_decommissioning_playbook(path: str, result: _EndpointResult, trigger_reason: str) -> None:
    """
    Run the 3-step decommissioning playbook for `path`.

    Steps execute sequentially; a failure in Step C is logged but does not
    prevent the Jira/Slack records from being retained.

    The workflow is registered in `_active_workflows` before Step A begins
    so the API can report 'running' status immediately.
    """

    wf = _build_workflow(path, result, trigger_reason)

    async with _workflow_lock:
        _active_workflows[path] = wf

    print(
        f"\n{'═'*70}\n"
        f"  [L3 PLAYBOOK START]  {wf.workflow_id}\n"
        f"  Path   : {path}\n"
        f"  Reason : {trigger_reason}\n"
        f"  Action : {wf.gateway_action.value}\n"
        f"{'═'*70}"
    )

    # ── Step A: Jira ──────────────────────────────────────────────────────────
    step_a = await _step_jira(wf)
    async with _workflow_lock:
        _active_workflows[path].steps[PlaybookStep.JIRA_TICKET] = step_a

    # ── Step B: Slack ─────────────────────────────────────────────────────────
    step_b = await _step_slack(wf)
    async with _workflow_lock:
        _active_workflows[path].steps[PlaybookStep.SLACK_ALERT] = step_b

    # ── Step C: Gateway rule ──────────────────────────────────────────────────
    step_c = await _step_gateway(wf)
    async with _workflow_lock:
        _active_workflows[path].steps[PlaybookStep.GATEWAY_RULE] = step_c

    # ── Finalise ──────────────────────────────────────────────────────────────
    all_done   = all(s.status == StepStatus.DONE   for s in [step_a, step_b, step_c])
    any_failed = any(s.status == StepStatus.FAILED for s in [step_a, step_b, step_c])
    status = "completed" if all_done else ("partial_failure" if any_failed else "completed")

    completed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    async with _workflow_lock:
        _active_workflows[path].overall_status = status
        _active_workflows[path].completed_at   = completed_at
        _completed_paths.add(path)

    print(
        f"\n{'═'*70}\n"
        f"  [L3 PLAYBOOK DONE]  {wf.workflow_id}  status={status}\n"
        f"  Jira  : {step_a.status.value}  |  "
        f"Slack : {step_b.status.value}  |  "
        f"Gateway : {step_c.status.value}\n"
        f"{'═'*70}\n"
    )


# ─────────────────────────────────────────────────────────────────────────────
# §7  Background Polling Loop
# ─────────────────────────────────────────────────────────────────────────────

async def _fetch_risk_scores() -> Optional[_RiskScoreResponse]:
    """Poll the Level 1/2 Risk Engine for the latest endpoint assessments."""
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_S) as client:
            resp = await client.get(RISK_ENGINE_URL)
            resp.raise_for_status()
            return _RiskScoreResponse(**resp.json())
    except httpx.ConnectError:
        print(f"[L3 POLL] Risk engine unreachable at {RISK_ENGINE_URL}")
        return None
    except httpx.HTTPStatusError as exc:
        print(f"[L3 POLL] Risk engine HTTP error: {exc.response.status_code}")
        return None
    except Exception as exc:
        print(f"[L3 POLL] Unexpected fetch error: {exc}")
        return None


def _build_trigger_reason(result: _EndpointResult) -> Optional[str]:
    """
    Return a human-readable trigger reason if the endpoint meets decommission
    criteria, or None if it should be skipped.

    Criteria (OR logic):
      1. lifecycle_risk > LIFECYCLE_RISK_FLOOR (80)
      2. Any flag contains 'ZOMBIE' or 'API_STATUS:ZOMBIE'
      3. composite risk_tier is CRITICAL
    """
    lr = result.lifecycle.lifecycle_risk
    flags_upper = " ".join(result.flags).upper()
    tier = result.composite.risk_tier

    reasons: list[str] = []

    if lr > LIFECYCLE_RISK_FLOOR:
        reasons.append(f"lifecycle_risk={lr} > threshold={LIFECYCLE_RISK_FLOOR}")

    if "ZOMBIE" in flags_upper:
        reasons.append(f"zombie flag detected ({', '.join(f for f in result.flags if 'ZOMBIE' in f.upper())})")

    if tier == "CRITICAL":
        reasons.append(f"composite risk_tier=CRITICAL (score={result.composite.composite_risk_score})")

    return "; ".join(reasons) if reasons else None


async def _polling_loop() -> None:
    """Background asyncio task — runs every POLL_INTERVAL_S seconds."""
    print(
        f"[L3 POLL] Orchestrator polling loop started.\n"
        f"  Risk Engine : {RISK_ENGINE_URL}\n"
        f"  Gateway     : {GATEWAY_RULES_URL}\n"
        f"  Interval    : {POLL_INTERVAL_S}s\n"
        f"  Trigger     : lifecycle_risk > {LIFECYCLE_RISK_FLOOR} "
        f"OR zombie flag OR CRITICAL tier\n"
    )

    while True:
        await asyncio.sleep(POLL_INTERVAL_S)

        risk_data = await _fetch_risk_scores()
        if not risk_data:
            continue

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"[{ts}] [L3 POLL] {len(risk_data.results)} endpoint(s) received from risk engine.")

        for result in risk_data.results:
            path = result.path

            # De-duplicate: never re-trigger a path that's already been handled.
            async with _workflow_lock:
                already_processed = path in _completed_paths or path in _active_workflows

            if already_processed:
                continue

            trigger_reason = _build_trigger_reason(result)
            if not trigger_reason:
                continue

            print(f"  → Triggering playbook for '{path}': {trigger_reason}")
            # Fire-and-forget so the polling loop is never blocked by one endpoint.
            asyncio.create_task(
                execute_decommissioning_playbook(path, result, trigger_reason)
            )


# ─────────────────────────────────────────────────────────────────────────────
# §8  FastAPI Application
# ─────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(_polling_loop())
    yield


app = FastAPI(
    title="ALIE — Level 3 Policy Orchestrator",
    description=(
        "Governance layer for the ALIE pipeline. Detects architectural risk "
        "(Zombie/Orphaned APIs), executes Jira + Slack + Gateway decommission "
        "playbooks, and exposes workflow state for Level 2 / dashboard consumption."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
async def health() -> dict:
    async with _workflow_lock:
        active  = {p: wf.overall_status for p, wf in _active_workflows.items()}
        completed_count = len(_completed_paths)
    return {
        "status":              "healthy",
        "service":             "alie-level3-policy-orchestrator",
        "version":             "1.0.0",
        "poll_interval_s":     POLL_INTERVAL_S,
        "lifecycle_threshold": LIFECYCLE_RISK_FLOOR,
        "risk_engine_url":     RISK_ENGINE_URL,
        "gateway_rules_url":   GATEWAY_RULES_URL,
        "active_workflows":    len(active),
        "completed_workflows": completed_count,
        "timestamp":           datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


# ── List all workflows ────────────────────────────────────────────────────────

@app.get("/api/v1/active-workflows", tags=["workflows"])
async def get_active_workflows(status_filter: Optional[str] = None) -> JSONResponse:
    """
    Return all decommissioning workflows (running and completed).

    Query parameters
    ----------------
    status_filter : "running" | "completed" | "partial_failure"
                    If omitted, all workflows are returned.
    """
    async with _workflow_lock:
        snapshot = {p: wf.dict() for p, wf in _active_workflows.items()}

    if status_filter:
        snapshot = {p: w for p, w in snapshot.items()
                    if w.get("overall_status") == status_filter}

    running   = sum(1 for w in snapshot.values() if w["overall_status"] == "running")
    completed = sum(1 for w in snapshot.values() if w["overall_status"] == "completed")
    failed    = sum(1 for w in snapshot.values() if w["overall_status"] == "partial_failure")

    return JSONResponse(content={
        "queried_at":   datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total":        len(snapshot),
        "running":      running,
        "completed":    completed,
        "partial_failure": failed,
        "workflows":    snapshot,
    })


# ── Single workflow detail ────────────────────────────────────────────────────

@app.get("/api/v1/workflows/{workflow_id}", tags=["workflows"])
async def get_workflow_by_id(workflow_id: str) -> JSONResponse:
    """Retrieve a specific workflow by its ID (e.g. WF-A3F9B1C042)."""
    async with _workflow_lock:
        match = next(
            (wf for wf in _active_workflows.values() if wf.workflow_id == workflow_id),
            None,
        )
    if match is None:
        return JSONResponse(
            status_code=404,
            content={"error": f"Workflow '{workflow_id}' not found.",
                     "known_ids": [wf.workflow_id for wf in _active_workflows.values()]},
        )
    return JSONResponse(content=match.dict())


# ── Manual trigger (for demos / testing) ─────────────────────────────────────

@app.post("/api/v1/trigger", tags=["workflows"], status_code=202)
async def manual_trigger(path: str, force: bool = False) -> dict:
    """
    Manually trigger the decommissioning playbook for `path`.

    Useful during demos to bypass the 10-second polling cycle.
    Pass `force=true` to re-trigger an already-completed workflow.
    """
    async with _workflow_lock:
        already = path in _completed_paths or path in _active_workflows

    if already and not force:
        return {
            "queued":  False,
            "reason":  f"'{path}' already has an active or completed workflow. "
                       "Pass ?force=true to override.",
            "path":    path,
        }

    if force:
        async with _workflow_lock:
            _completed_paths.discard(path)
            _active_workflows.pop(path, None)

    # Build a synthetic risk result for manual triggers.
    synthetic = _EndpointResult(
        path=path,
        lifecycle=_LifecycleSnap(lifecycle_risk=85.0, confidence_pct=75.0, lifecycle_weighted=63.75),
        ml=_MLSnap(ml_probability_factor=0.82, ml_score=82.0, signals_fired=["manual-trigger"]),
        composite=_CompositeSnap(
            composite_risk_score=85.0,
            risk_tier="CRITICAL",
            recommended_action="Manual decommission triggered.",
        ),
        flags=["API_STATUS:ZOMBIE", "MANUAL_TRIGGER"],
    )

    asyncio.create_task(
        execute_decommissioning_playbook(path, synthetic, "manual trigger via /api/v1/trigger")
    )

    return {
        "queued": True,
        "path":   path,
        "note":   "Playbook started asynchronously. Poll /api/v1/active-workflows for status.",
    }


# ── Rollback: remove gateway rule and archive workflow ────────────────────────

@app.post("/api/v1/workflows/{workflow_id}/rollback", tags=["workflows"])
async def rollback_workflow(workflow_id: str) -> JSONResponse:
    """
    Stub rollback endpoint (linked from the Slack alert).

    In production this would DELETE the gateway rule via
    DELETE /admin/rules/{rule_id} and mark the workflow as rolled back.
    For the PoC it returns the would-be rollback payload.
    """
    async with _workflow_lock:
        match = next(
            (wf for wf in _active_workflows.values() if wf.workflow_id == workflow_id),
            None,
        )
    if match is None:
        return JSONResponse(status_code=404, content={"error": f"Workflow '{workflow_id}' not found."})

    gateway_step = match.steps.get(PlaybookStep.GATEWAY_RULE)
    rule_id = None
    if gateway_step and gateway_step.payload:
        rule_id = gateway_step.payload.get("gateway_response", {}).get("rule_id")

    return JSONResponse(content={
        "workflow_id":   workflow_id,
        "path":          match.path,
        "rollback_note": (
            f"Would call DELETE {GATEWAY_RULES_URL}/{rule_id} to remove the "
            f"{match.gateway_action.value} rule from the gateway. "
            "Implement full rollback in Part 5 (Dashboard)."
        ),
        "gateway_rule_id": rule_id,
        "status": "stub — rollback logged but not executed in PoC",
    })


# ─────────────────────────────────────────────────────────────────────────────
# §9  Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ALIE Level 3 — Policy Orchestrator (Decommissioner)"
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=8004, type=int)
    args = parser.parse_args()

    uvicorn.run(
        "level3_policy_orchestrator:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="warning",   # engine prints its own structured output
    )
