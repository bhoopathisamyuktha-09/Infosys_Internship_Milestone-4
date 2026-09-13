"""
routes/risk_routes.py — Milestone 3 Risk Scoring & Prioritization API Routes
============================================================================
Milestone 3: Risk Prioritization & Security Intelligence

Provides:
  1. POST /api/v1/risk/calculate
  2. GET  /api/v1/risk/high
  3. GET  /api/v1/risk/summary
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status

from database.incident_repository import (
    get_high_risk_incidents,
    get_risk_summary,
)
from database.risk_weights_repository import (
    get_active_risk_weights,
    reset_risk_weights,
    save_risk_weights,
)
from models.m3_schemas import (
    RiskCalculateRequest,
    RiskCalculateResponse,
    RiskSummaryResponse,
    RiskWeightsModel,
    RiskWeightsUpdateRequest,
)
from services.incident_service import process_event_to_incident

log = logging.getLogger("routes.risk_routes")

router = APIRouter(prefix="/api/v1/risk", tags=["M3 - Risk Intelligence"])


@router.get(
    "/weights",
    response_model=RiskWeightsModel,
    summary="Get Active 5-Factor Risk Weights",
    status_code=status.HTTP_200_OK,
)
def get_weights():
    """Retrieve the currently active 5-factor risk weights."""
    try:
        weights = get_active_risk_weights()
        return RiskWeightsModel(**weights)
    except Exception as e:
        log.error(f"Error retrieving risk weights: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error retrieving risk weights.")


@router.put(
    "/weights",
    response_model=RiskWeightsModel,
    summary="Update Active 5-Factor Risk Weights",
    status_code=status.HTTP_200_OK,
)
def update_weights(req: RiskWeightsUpdateRequest):
    """
    Update active 5-factor risk weights.
    Validation: each weight in [0, 1] and all five must sum to exactly 1.0.
    """
    w_dict = req.model_dump()
    weights_list = [
        w_dict["threat_severity"],
        w_dict["ml_confidence"],
        w_dict["asset_criticality"],
        w_dict["vulnerability_cvss"],
        w_dict["threat_intelligence"],
    ]

    for w in weights_list:
        if w < 0.0 or w > 1.0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Every risk weight must be between 0.0 and 1.0.",
            )

    total = sum(weights_list)
    if round(total, 4) != 1.0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Risk weights must sum to exactly 1.0 (current sum: {round(total, 4)}).",
        )

    try:
        saved = save_risk_weights(w_dict)
        return RiskWeightsModel(**saved)
    except Exception as e:
        log.error(f"Error updating risk weights: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error updating risk weights.")


@router.post(
    "/weights/reset",
    response_model=RiskWeightsModel,
    summary="Reset Risk Weights to Defaults",
    status_code=status.HTTP_200_OK,
)
def reset_weights_route():
    """Reset active 5-factor risk weights back to default values (0.25, 0.25, 0.20, 0.20, 0.10)."""
    try:
        saved = reset_risk_weights()
        return RiskWeightsModel(**saved)
    except Exception as e:
        log.error(f"Error resetting risk weights: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error resetting risk weights.")



@router.post(
    "/calculate",
    response_model=RiskCalculateResponse,
    summary="Calculate M3 Risk & Context for a Security Event",
    status_code=status.HTTP_200_OK,
)
def calculate_event_risk(req: RiskCalculateRequest):
    """
    Given an event_id, runs the full M3 enrichment, correlation, attack chain,
    and Phase 1 deterministic risk calculation pipeline.
    """
    event_id = req.event_id.strip()
    if not event_id:
        raise HTTPException(status_code=400, detail="event_id must not be empty.")

    try:
        # Run pipeline and return result (does not require previous incident creation)
        incident_data = process_event_to_incident(event_id=event_id, persist=True)
        return RiskCalculateResponse(
            event_id=event_id,
            risk_score=incident_data["risk_score"],
            risk_level=incident_data["risk_level"],
            priority=incident_data["priority"],
            risk_breakdown=incident_data["risk_breakdown"],
            risk_score_comparison=incident_data.get("risk_score_comparison"),
            reasons=incident_data["reasons"],
            related_events_count=incident_data["related_events_count"],
            attack_chain=incident_data.get("attack_chain"),
        )
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        log.error(f"Error calculating risk for '{event_id}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error calculating risk.")


@router.get(
    "/high",
    summary="Get High & Critical Risk Incidents",
    status_code=status.HTTP_200_OK,
)
def get_high_risk(
    limit: int = Query(50, ge=1, le=500, description="Max items to return"),
    skip: int = Query(0, ge=0, description="Offset"),
    min_score: int = Query(61, ge=0, le=100, description="Minimum risk score threshold (default 61 for High)"),
):
    """
    Retrieve incidents above the high-risk threshold (score >= 61),
    sorted in descending order by risk score.
    """
    try:
        items, total = get_high_risk_incidents(min_score=min_score, limit=limit, skip=skip)
        return {
            "total": total,
            "min_score": min_score,
            "items": items,
        }
    except Exception as e:
        log.error(f"Error retrieving high-risk incidents: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error retrieving high risk incidents.")


@router.get(
    "/summary",
    response_model=RiskSummaryResponse,
    summary="Get Risk Overview Summary & Metrics",
    status_code=status.HTTP_200_OK,
)
def get_summary():
    """
    Retrieve aggregate metrics and distributions for the M3 Risk Overview Dashboard.
    """
    try:
        summary_data = get_risk_summary()
        return RiskSummaryResponse(**summary_data)
    except Exception as e:
        log.error(f"Error retrieving risk summary: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error retrieving risk summary.")
