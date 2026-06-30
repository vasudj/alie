"""
ALIE — Advanced Composite Risk Engine  (Level 1 — upgraded)
============================================================
Part 2b of the ALIE 5-part security pipeline.

Replaces the basic statistical `level1_ai_engine.py` with a
production-grade two-track model:

  Track A  Deterministic Lifecycle Risk Calculator
           Structured scoring via Base Status + Evidence + Exposure +
           Business Criticality, weighted by a Confidence score derived
           from how much evidence was actually matched.

  Track B  Behavioral ML Probability Factor
           A transparent, auditable mock of a trained classifier.
           Evaluates payload_volatility, error_rate, and velocity against
           calibrated thresholds to emit a zombie probability (0.0 → 1.0).

  Final    Composite Risk Formula
           Highest_Weighted_Detector
           + 0.30 × SUM(Remaining_Weighted_Detectors)   [0 for PoC]
           + API_Lifecycle_Weighted_Score
           + Reputation_Penalty                          [0 for PoC]
           → clamped to [0, 100]

Run:
    python advanced_risk_engine.py [--port 8002] [--host 0.0.0.0]
"""

from __future__ import annotations

import argparse
import math
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ─────────────────────────────────────────────────────────────────────────────
# §0  Utility
# ─────────────────────────────────────────────────────────────────────────────

def clamp(value: float, min_val: float = 0.0, max_val: float = 100.0) -> float:
    """Safely bound a score to [min_val, max_val]."""
    return max(min_val, min(max_val, value))


# ─────────────────────────────────────────────────────────────────────────────
# §1  Deterministic Lifecycle Risk Model — Enums & Point Tables
# ─────────────────────────────────────────────────────────────────────────────

class APIStatus(str, Enum):
    ACTIVE     = "Active"
    DEPRECATED = "Deprecated"
    ORPHANED   = "Orphaned"
    SHADOW     = "Shadow"
    ZOMBIE     = "Zombie"


class ExposureLevel(str, Enum):
    INTERNAL = "Internal"
    PARTNER  = "Partner"
    PUBLIC   = "Public Internet"


class BusinessCriticality(str, Enum):
    HEALTH    = "Health"
    CUSTOMER  = "Customer"
    FINANCIAL = "Financial"
    PAYMENT   = "Payment"
    ADMIN     = "Admin"


# ── Point tables (single source of truth) ─────────────────────────────────────

BASE_STATUS_SCORES: Dict[APIStatus, int] = {
    APIStatus.ACTIVE:     0,
    APIStatus.DEPRECATED: 20,
    APIStatus.ORPHANED:   45,
    APIStatus.SHADOW:     65,
    APIStatus.ZOMBIE:     80,
}

EXPOSURE_SCORES: Dict[ExposureLevel, int] = {
    ExposureLevel.INTERNAL: 0,
    ExposureLevel.PARTNER:  5,
    ExposureLevel.PUBLIC:   15,
}

CRITICALITY_SCORES: Dict[BusinessCriticality, int] = {
    BusinessCriticality.HEALTH:    0,
    BusinessCriticality.CUSTOMER:  10,
    BusinessCriticality.FINANCIAL: 20,
    BusinessCriticality.PAYMENT:   25,
    BusinessCriticality.ADMIN:     30,
}

# Evidence items: key → (display label, point value)
# Maximum possible evidence score = sum of all values = 40
EVIDENCE_ITEMS: Dict[str, tuple[str, int]] = {
    "missing_openapi":    ("Missing OpenAPI Spec",       10),
    "missing_inventory":  ("Missing API Inventory Entry", 10),
    "no_owner":           ("No Registered Owner",         10),
    "runtime_seen":       ("Seen at Runtime (unplanned)",  5),
    "no_cicd":            ("No CI/CD Pipeline Entry",      5),
}
TOTAL_EVIDENCE_WEIGHT: int = sum(v for _, v in EVIDENCE_ITEMS.values())   # 40


# ─────────────────────────────────────────────────────────────────────────────
# §2  Pydantic Input/Output Models
# ─────────────────────────────────────────────────────────────────────────────

class EvidenceFlags(BaseModel):
    """Boolean flags for each evidence dimension."""
    missing_openapi:   bool = False
    missing_inventory: bool = False
    no_owner:          bool = False
    runtime_seen:      bool = False
    no_cicd:           bool = False


class EndpointBehavior(BaseModel):
    """Live behavioral metrics fed from the Level 1 statistical engine."""
    velocity_rpm:       float = Field(0.0,   description="Requests per minute (last window)")
    error_rate:         float = Field(0.0,   description="Fraction of 4xx/5xx responses [0–1]")
    payload_volatility: float = Field(0.0,   description="Std-dev of response_bytes")
    mean_response_bytes: float = Field(0.0,  description="Mean response body size in bytes")
    sample_count:       int   = Field(0,     description="Observations in the current window")


class EndpointDefinition(BaseModel):
    """Full descriptor for a single API endpoint under assessment."""
    path:           str
    status:         APIStatus
    exposure:       ExposureLevel
    criticality:    BusinessCriticality
    evidence:       EvidenceFlags
    behavior:       EndpointBehavior
    tags:           List[str] = Field(default_factory=list)
    description:    Optional[str] = None


# ── Output sub-models ─────────────────────────────────────────────────────────

class LifecycleBreakdown(BaseModel):
    base_status_score:    int
    evidence_score:       int
    matched_evidence:     Dict[str, int]    # label → points
    exposure_score:       int
    criticality_score:    int
    lifecycle_risk:       float             # clamped sum
    confidence_pct:       float             # 0–100
    lifecycle_weighted:   float             # lifecycle_risk × (confidence/100)


class MLBreakdown(BaseModel):
    ml_probability_factor: float           # 0.0 – 1.0
    ml_score:              float           # mapped to 0–100
    signals_fired:         List[str]       # human-readable explanation
    model_version:         str


class CompositeBreakdown(BaseModel):
    highest_weighted_detector:  float      # max(ml_score, lifecycle_weighted)
    remaining_detectors_sum:    float      # 0 for PoC
    lifecycle_weighted_score:   float
    reputation_penalty:         float      # 0 for PoC
    composite_risk_score:       float      # final clamped [0–100]
    risk_tier:                  str        # CRITICAL / HIGH / MEDIUM / LOW / MINIMAL


class EndpointRiskReport(BaseModel):
    path:        str
    assessed_at: str
    lifecycle:   LifecycleBreakdown
    ml:          MLBreakdown
    composite:   CompositeBreakdown
    flags:       List[str]               # aggregated human-readable flag list
    recommended_action: str


# ─────────────────────────────────────────────────────────────────────────────
# §3  Track A — Deterministic Lifecycle Risk Calculator
# ─────────────────────────────────────────────────────────────────────────────

class LifecycleRiskCalculator:
    """
    Implements the deterministic branch of the ALIE Composite Risk Model.

    Formula
    -------
    Lifecycle_Risk = clamp(Base_Status + Evidence + Exposure + Criticality, 0, 100)
    Confidence     = (Matched_Evidence_Weight / TOTAL_EVIDENCE_WEIGHT) * 100
    Weighted_Score = Lifecycle_Risk × (Confidence / 100)
    """

    def calculate(self, ep: EndpointDefinition) -> LifecycleBreakdown:
        base   = BASE_STATUS_SCORES[ep.status]
        exp    = EXPOSURE_SCORES[ep.exposure]
        crit   = CRITICALITY_SCORES[ep.criticality]

        # Evidence: iterate flag dict, accumulate matched points.
        evidence_flags = ep.evidence.dict()
        matched: Dict[str, int] = {}
        evidence_total = 0

        for key, (label, points) in EVIDENCE_ITEMS.items():
            if evidence_flags.get(key, False):
                matched[label] = points
                evidence_total += points

        evidence_score = min(evidence_total, 40)   # hard cap per spec

        lifecycle_risk    = clamp(base + evidence_score + exp + crit)
        confidence_pct    = (evidence_total / TOTAL_EVIDENCE_WEIGHT) * 100.0
        lifecycle_weighted = lifecycle_risk * (confidence_pct / 100.0)

        return LifecycleBreakdown(
            base_status_score=base,
            evidence_score=evidence_score,
            matched_evidence=matched,
            exposure_score=exp,
            criticality_score=crit,
            lifecycle_risk=round(lifecycle_risk, 2),
            confidence_pct=round(confidence_pct, 2),
            lifecycle_weighted=round(lifecycle_weighted, 2),
        )


# ─────────────────────────────────────────────────────────────────────────────
# §4  Track B — Behavioral ML Probability Factor (transparent mock)
# ─────────────────────────────────────────────────────────────────────────────

class BehavioralMLPredictor:
    """
    Transparent mock of a trained binary classifier (zombie vs. benign).

    In production this class would load a serialised scikit-learn or ONNX
    model, call `predict_proba`, and return the positive-class probability.

    For the PoC we replicate what such a model would learn by hard-coding
    the decision logic it would approximate after training on labelled
    gateway logs.  The thresholds and weights are taken from the ALIE
    threat model rather than being arbitrary.

    Probability ranges
    ------------------
    0.90 – 0.99   Extremely high confidence zombie / malicious
    0.70 – 0.89   High confidence anomaly
    0.40 – 0.69   Suspicious — warrants investigation
    0.10 – 0.39   Elevated but plausible legitimate traffic
    0.01 – 0.09   Normal / benign
    """

    MODEL_VERSION = "alie-behavioral-mock-v1.2"

    # Feature thresholds calibrated against the ALIE threat model.
    PAYLOAD_VOL_CRITICAL  = 15_000.0   # stdev bytes — zombie ledger trap
    PAYLOAD_VOL_HIGH      =  5_000.0
    PAYLOAD_VOL_MEDIUM    =  1_000.0

    VELOCITY_CRITICAL     = 500.0      # rpm — volumetric DoS
    VELOCITY_HIGH         = 150.0
    VELOCITY_MEDIUM       =  60.0

    ERROR_RATE_CRITICAL   = 0.50       # fraction
    ERROR_RATE_HIGH       = 0.25
    ERROR_RATE_MEDIUM     = 0.10

    def predict_proba(self, behavior: EndpointBehavior) -> tuple[float, list[str]]:
        """
        Return (ml_probability_factor [0.0–1.0], signals_fired).

        The probability is built by adding independent signal contributions
        and then mapping through a sigmoid-like squash so the output stays
        in [0, 1] without any single signal dominating.
        """
        signals: list[str] = []
        raw_score: float   = 0.0

        # ── Signal 1: Payload Volatility (primary zombie detector) ────────────
        pv = behavior.payload_volatility
        if pv >= self.PAYLOAD_VOL_CRITICAL:
            raw_score += 0.70
            signals.append(
                f"CRITICAL payload volatility (stdev={pv:.0f}B ≥ {self.PAYLOAD_VOL_CRITICAL:.0f}B)"
            )
        elif pv >= self.PAYLOAD_VOL_HIGH:
            raw_score += 0.40
            signals.append(
                f"HIGH payload volatility (stdev={pv:.0f}B ≥ {self.PAYLOAD_VOL_HIGH:.0f}B)"
            )
        elif pv >= self.PAYLOAD_VOL_MEDIUM:
            raw_score += 0.15
            signals.append(
                f"ELEVATED payload volatility (stdev={pv:.0f}B ≥ {self.PAYLOAD_VOL_MEDIUM:.0f}B)"
            )

        # ── Signal 2: Velocity (DoS / scraper pattern) ────────────────────────
        vel = behavior.velocity_rpm
        if vel >= self.VELOCITY_CRITICAL:
            raw_score += 0.50
            signals.append(
                f"CRITICAL velocity ({vel:.1f} rpm ≥ {self.VELOCITY_CRITICAL:.0f})"
            )
        elif vel >= self.VELOCITY_HIGH:
            raw_score += 0.25
            signals.append(
                f"HIGH velocity ({vel:.1f} rpm ≥ {self.VELOCITY_HIGH:.0f})"
            )
        elif vel >= self.VELOCITY_MEDIUM:
            raw_score += 0.10
            signals.append(
                f"ELEVATED velocity ({vel:.1f} rpm ≥ {self.VELOCITY_MEDIUM:.0f})"
            )

        # ── Signal 3: Error Rate ──────────────────────────────────────────────
        er = behavior.error_rate
        if er >= self.ERROR_RATE_CRITICAL:
            raw_score += 0.35
            signals.append(
                f"CRITICAL error rate ({er*100:.1f}% ≥ {self.ERROR_RATE_CRITICAL*100:.0f}%)"
            )
        elif er >= self.ERROR_RATE_HIGH:
            raw_score += 0.20
            signals.append(
                f"HIGH error rate ({er*100:.1f}% ≥ {self.ERROR_RATE_HIGH*100:.0f}%)"
            )
        elif er >= self.ERROR_RATE_MEDIUM:
            raw_score += 0.08
            signals.append(
                f"ELEVATED error rate ({er*100:.1f}% ≥ {self.ERROR_RATE_MEDIUM*100:.0f}%)"
            )

        # ── Signal 4: Thin sample — low confidence bonus ──────────────────────
        if behavior.sample_count < 5 and behavior.sample_count > 0:
            raw_score += 0.05
            signals.append(
                f"LOW sample count ({behavior.sample_count} obs) — uncertainty penalty"
            )

        # ── Sigmoid squash → [0.01, 0.99] ────────────────────────────────────
        # Using a shifted sigmoid so raw_score=0 → ~0.05 (baseline benign)
        # and raw_score=1.5 → ~0.97 (near-certain zombie).
        prob = 1.0 / (1.0 + math.exp(-3.5 * (raw_score - 0.5)))
        prob = round(max(0.01, min(0.99, prob)), 4)

        if not signals:
            signals.append("No anomalous signals detected — baseline benign behaviour")

        return prob, signals


# ─────────────────────────────────────────────────────────────────────────────
# §5  Composite Risk Formula
# ─────────────────────────────────────────────────────────────────────────────

def _risk_tier(score: float) -> tuple[str, str]:
    """Map a composite score to (tier_label, recommended_action)."""
    if score >= 80:
        return "CRITICAL",   "Immediate decommission + block at gateway. Escalate to CISO."
    if score >= 60:
        return "HIGH",       "Schedule decommission within 72 hours. Push Brownout rule to gateway."
    if score >= 40:
        return "MEDIUM",     "Investigate ownership. Add to deprecation backlog."
    if score >= 20:
        return "LOW",        "Monitor. Request owner acknowledgement."
    return     "MINIMAL",    "No action required. Re-assess in next cycle."


def compute_composite(
    lifecycle: LifecycleBreakdown,
    ml_prob: float,
) -> CompositeBreakdown:
    """
    ALIE Final Composite Risk Formula
    ----------------------------------
    ml_score           = ml_probability_factor × 100   (maps 0–1 → 0–100)

    highest_detector   = max(ml_score, lifecycle_weighted)
    remaining_sum      = 0   (PoC; future: WAF score, threat-intel feed, etc.)
    reputation_penalty = 0   (PoC; future: CVE hits, dark-web mentions)

    Composite_Risk = clamp(
        highest_detector
        + 0.30 × remaining_sum
        + lifecycle_weighted
        + reputation_penalty,
        0, 100
    )
    """
    ml_score           = round(ml_prob * 100.0, 2)
    lw                 = lifecycle.lifecycle_weighted
    highest_detector   = max(ml_score, lw)
    remaining_sum      = 0.0      # extended in Part 3+
    reputation_penalty = 0.0      # extended in Part 3+

    raw_composite = (
        highest_detector
        + 0.30 * remaining_sum
        + lw
        + reputation_penalty
    )
    composite = round(clamp(raw_composite), 2)
    tier, action = _risk_tier(composite)

    return CompositeBreakdown(
        highest_weighted_detector=round(highest_detector, 2),
        remaining_detectors_sum=remaining_sum,
        lifecycle_weighted_score=round(lw, 2),
        reputation_penalty=reputation_penalty,
        composite_risk_score=composite,
        risk_tier=tier,
        recommended_action=action,   # type: ignore[call-arg]  — injected below
    )


# ─────────────────────────────────────────────────────────────────────────────
# §6  Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

_lifecycle_calc = LifecycleRiskCalculator()
_ml_predictor   = BehavioralMLPredictor()


def assess_endpoint(ep: EndpointDefinition) -> EndpointRiskReport:
    """Run both scoring tracks and merge into a single EndpointRiskReport."""

    # Track A
    lifecycle = _lifecycle_calc.calculate(ep)

    # Track B
    ml_prob, ml_signals = _ml_predictor.predict_proba(ep.behavior)
    ml_score = round(ml_prob * 100.0, 2)
    ml = MLBreakdown(
        ml_probability_factor=ml_prob,
        ml_score=ml_score,
        signals_fired=ml_signals,
        model_version=BehavioralMLPredictor.MODEL_VERSION,
    )

    # Composite
    composite = compute_composite(lifecycle, ml_prob)

    # Aggregate human-readable flags
    flags: list[str] = []
    if lifecycle.base_status_score >= 65:
        flags.append(f"API_STATUS:{ep.status.value.upper()}")
    if lifecycle.evidence_score >= 20:
        flags.append("EVIDENCE:MULTIPLE_MISSING")
    if lifecycle.exposure_score >= 15:
        flags.append("EXPOSURE:PUBLIC_INTERNET")
    if lifecycle.criticality_score >= 25:
        flags.append(f"CRITICALITY:{ep.criticality.value.upper()}")
    if ml_prob >= 0.70:
        flags.append(f"ML:HIGH_ZOMBIE_PROBABILITY({ml_prob:.2f})")
    if ep.behavior.payload_volatility >= BehavioralMLPredictor.PAYLOAD_VOL_HIGH:
        flags.append(f"PAYLOAD_VOLATILITY:{ep.behavior.payload_volatility:.0f}B_STDEV")

    _, action = _risk_tier(composite.composite_risk_score)

    return EndpointRiskReport(
        path=ep.path,
        assessed_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        lifecycle=lifecycle,
        ml=ml,
        composite=CompositeBreakdown(
            **{**composite.dict(), "recommended_action": action}
        ),
        flags=flags,
        recommended_action=action,
    )


# ─────────────────────────────────────────────────────────────────────────────
# §7  In-memory Endpoint Registry  (seed data for PoC)
# ─────────────────────────────────────────────────────────────────────────────

_ENDPOINT_REGISTRY: Dict[str, EndpointDefinition] = {

    # ── Endpoint 1: Healthy modern transfer API ───────────────────────────────
    "/bank/api/v2/accounts/transfer": EndpointDefinition(
        path="/bank/api/v2/accounts/transfer",
        status=APIStatus.ACTIVE,
        exposure=ExposureLevel.INTERNAL,
        criticality=BusinessCriticality.FINANCIAL,
        evidence=EvidenceFlags(
            missing_openapi=False,
            missing_inventory=False,
            no_owner=False,
            runtime_seen=False,
            no_cicd=False,
        ),
        behavior=EndpointBehavior(
            velocity_rpm=42.5,
            error_rate=0.02,
            payload_volatility=312.0,
            mean_response_bytes=480.0,
            sample_count=850,
        ),
        tags=["payment", "core-banking", "v2"],
        description="Secure account-to-account funds transfer (modern v2 API).",
    ),

    # ── Endpoint 2: Zombie legacy ledger — the trap ───────────────────────────
    "/bank/api/v1/reports/legacy-ledger": EndpointDefinition(
        path="/bank/api/v1/reports/legacy-ledger",
        status=APIStatus.ZOMBIE,
        exposure=ExposureLevel.PUBLIC,
        criticality=BusinessCriticality.ADMIN,
        evidence=EvidenceFlags(
            missing_openapi=True,    # +10  was never added to the spec
            missing_inventory=True,  # +10  not in the API catalogue
            no_owner=True,           # +10  originating team disbanded
            runtime_seen=True,       #  +5  gateway still sees traffic
            no_cicd=False,           #  old pipeline entry exists (stale)
        ),
        behavior=EndpointBehavior(
            velocity_rpm=7.5,            # low-and-slow — zombie scraper cadence
            error_rate=0.04,
            payload_volatility=21_840.0, # >21 KB stdev — massive bloat variance
            mean_response_bytes=54_200.0,
            sample_count=38,
        ),
        tags=["legacy", "deprecated", "zombie", "batch", "v1"],
        description="Decommissioned nightly ledger export. Never removed from codebase.",
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# §8  FastAPI Application
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ALIE — Advanced Composite Risk Engine",
    description=(
        "Two-track (Deterministic Lifecycle + Behavioral ML) risk scoring for "
        "API endpoints. Feeds Level 2 (Rule Engine) and Level 3 (Decommission Engine)."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
def health() -> dict:
    return {
        "status":             "healthy",
        "service":            "alie-advanced-risk-engine",
        "version":            "2.0.0",
        "endpoints_in_registry": len(_ENDPOINT_REGISTRY),
        "ml_model":           BehavioralMLPredictor.MODEL_VERSION,
        "timestamp":          datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


# ── Full risk assessment for all registered endpoints ─────────────────────────

@app.get("/api/v1/risk-scores", tags=["scoring"])
def get_all_risk_scores(min_score: float = 0.0) -> JSONResponse:
    """
    Return the full composite risk assessment for every endpoint in the
    registry.  Sorted by composite_risk_score descending.

    Query parameters
    ----------------
    min_score : Only include endpoints with composite_risk_score ≥ this value.
    """
    reports = [assess_endpoint(ep) for ep in _ENDPOINT_REGISTRY.values()]
    reports.sort(key=lambda r: -r.composite.composite_risk_score)

    filtered = [r for r in reports if r.composite.composite_risk_score >= min_score]

    critical = [r.path for r in filtered if r.composite.risk_tier == "CRITICAL"]
    high     = [r.path for r in filtered if r.composite.risk_tier == "HIGH"]

    return JSONResponse(content={
        "generated_at":    datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_assessed":  len(reports),
        "returned":        len(filtered),
        "critical_paths":  critical,
        "high_risk_paths": high,
        "results": [r.dict() for r in filtered],
    })


# ── Single-endpoint assessment ────────────────────────────────────────────────

@app.get("/api/v1/risk-scores/path", tags=["scoring"])
def get_risk_score_for_path(path: str) -> JSONResponse:
    """
    Return the detailed composite risk assessment for one specific path.

    Example:
        GET /api/v1/risk-scores/path?path=/bank/api/v1/reports/legacy-ledger
    """
    ep = _ENDPOINT_REGISTRY.get(path)
    if ep is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": f"Path '{path}' is not in the registry.",
                "registered_paths": list(_ENDPOINT_REGISTRY.keys()),
            },
        )
    return JSONResponse(content=assess_endpoint(ep).dict())


# ── Register / update an endpoint dynamically ─────────────────────────────────

@app.post("/api/v1/endpoints", tags=["registry"], status_code=201)
def register_endpoint(ep: EndpointDefinition) -> dict:
    """
    Add or update an endpoint in the in-memory registry.
    Allows Level 3 (Decommission Engine) to inject newly discovered APIs.
    """
    _ENDPOINT_REGISTRY[ep.path] = ep
    report = assess_endpoint(ep)
    return {
        "registered": ep.path,
        "composite_risk_score": report.composite.composite_risk_score,
        "risk_tier": report.composite.risk_tier,
        "recommended_action": report.recommended_action,
    }


# ── Delete an endpoint from registry ─────────────────────────────────────────

@app.delete("/api/v1/endpoints", tags=["registry"])
def deregister_endpoint(path: str) -> dict:
    """Remove an endpoint from the registry (post-decommission clean-up)."""
    if path not in _ENDPOINT_REGISTRY:
        return JSONResponse(
            status_code=404,
            content={"error": f"Path '{path}' not found in registry."},
        )
    _ENDPOINT_REGISTRY.pop(path)
    return {"deregistered": path, "remaining": len(_ENDPOINT_REGISTRY)}


# ── Formula reference ─────────────────────────────────────────────────────────

@app.get("/api/v1/model-info", tags=["ops"])
def model_info() -> dict:
    """Return the scoring model configuration for auditability."""
    return {
        "model_version": BehavioralMLPredictor.MODEL_VERSION,
        "tracks": {
            "A_deterministic": {
                "base_status_scores":   {k.value: v for k, v in BASE_STATUS_SCORES.items()},
                "exposure_scores":      {k.value: v for k, v in EXPOSURE_SCORES.items()},
                "criticality_scores":   {k.value: v for k, v in CRITICALITY_SCORES.items()},
                "evidence_items":       {k: {"label": l, "points": p}
                                         for k, (l, p) in EVIDENCE_ITEMS.items()},
                "total_evidence_weight": TOTAL_EVIDENCE_WEIGHT,
                "formula": (
                    "Lifecycle_Risk   = clamp(Base + Evidence + Exposure + Criticality, 0, 100)\n"
                    "Confidence       = (matched_evidence_weight / 40) × 100\n"
                    "Lifecycle_Weighted = Lifecycle_Risk × (Confidence / 100)"
                ),
            },
            "B_ml": {
                "model_type": "BehavioralMLPredictor (calibrated mock)",
                "features":   ["payload_volatility", "velocity_rpm", "error_rate", "sample_count"],
                "output":     "ml_probability_factor ∈ [0.01, 0.99]",
                "thresholds": {
                    "payload_volatility_bytes": {
                        "CRITICAL": BehavioralMLPredictor.PAYLOAD_VOL_CRITICAL,
                        "HIGH":     BehavioralMLPredictor.PAYLOAD_VOL_HIGH,
                        "MEDIUM":   BehavioralMLPredictor.PAYLOAD_VOL_MEDIUM,
                    },
                    "velocity_rpm": {
                        "CRITICAL": BehavioralMLPredictor.VELOCITY_CRITICAL,
                        "HIGH":     BehavioralMLPredictor.VELOCITY_HIGH,
                        "MEDIUM":   BehavioralMLPredictor.VELOCITY_MEDIUM,
                    },
                    "error_rate": {
                        "CRITICAL": BehavioralMLPredictor.ERROR_RATE_CRITICAL,
                        "HIGH":     BehavioralMLPredictor.ERROR_RATE_HIGH,
                        "MEDIUM":   BehavioralMLPredictor.ERROR_RATE_MEDIUM,
                    },
                },
            },
        },
        "composite_formula": (
            "ml_score              = ml_probability_factor × 100\n"
            "highest_detector      = max(ml_score, lifecycle_weighted)\n"
            "Composite_Risk        = clamp(\n"
            "    highest_detector\n"
            "    + 0.30 × remaining_detectors_sum   [0 in PoC]\n"
            "    + lifecycle_weighted\n"
            "    + reputation_penalty               [0 in PoC],\n"
            "    0, 100\n"
            ")"
        ),
        "risk_tiers": {
            "CRITICAL":  "score ≥ 80",
            "HIGH":      "score ≥ 60",
            "MEDIUM":    "score ≥ 40",
            "LOW":       "score ≥ 20",
            "MINIMAL":   "score < 20",
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# §9  Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ALIE Advanced Composite Risk Engine"
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=8002, type=int)
    args = parser.parse_args()

    uvicorn.run(
        "advanced_risk_engine:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="info",
    )
