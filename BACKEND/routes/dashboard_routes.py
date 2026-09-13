"""
routes/dashboard_routes.py — Milestone 4 Dashboard & Executive Analytics Routes
================================================================================
Milestone 4: Backend Final Integration, API Completion & Production Hardening

Provides:
  1. GET /api/v1/dashboard/overview         - Consolidated dynamic SOC Overview
  2. GET /api/v1/dashboard/security-posture  - Deterministic 0-100 Security Posture
  3. GET /api/v1/executive/summary          - Executive Security Briefing Summary
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status

from models.m4_schemas import (
    DashboardOverviewResponse,
    ExecutiveSummaryResponse,
    SecurityPostureResponse,
)
from services import dashboard_service

log = logging.getLogger("routes.dashboard_routes")

router = APIRouter(prefix="/api/v1", tags=["M4 - Dashboard & Executive Analytics"])


@router.get(
    "/dashboard/overview",
    response_model=DashboardOverviewResponse,
    summary="Get Consolidated SOC Overview Dashboard Aggregations",
    status_code=status.HTTP_200_OK,
)
def get_dashboard_overview(
    time_range: str = Query("all", pattern="^(24h|7d|30d|all)$", description="Relative time window: 24h, 7d, 30d, all"),
    start_date: Optional[str] = Query(None, description="Filter from timestamp/date (YYYY-MM-DD or ISO)"),
    end_date: Optional[str] = Query(None, description="Filter until timestamp/date (YYYY-MM-DD or ISO)"),
):
    """
    Retrieve dynamically calculated SOC Overview metrics from MongoDB telemetry.
    Supports dynamic relative time windows (24h, 7d, 30d) and explicit date ranges.
    Calculates zero hardcoded metrics.
    """
    try:
        overview_data = dashboard_service.calculate_dashboard_overview(
            time_range=time_range,
            start_date=start_date,
            end_date=end_date,
        )
        return DashboardOverviewResponse(**overview_data)
    except Exception as e:
        log.error(f"Error calculating dashboard overview: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error computing dashboard overview.",
        )


@router.get(
    "/dashboard/security-posture",
    response_model=SecurityPostureResponse,
    summary="Get Deterministic 0-100 Security Posture Score & Explanations",
    status_code=status.HTTP_200_OK,
)
def get_security_posture():
    """
    Compute deterministic organizational Security Posture on a 0-100 scale.
    Calculates deductions from live database metrics:
      - Active & High-Risk Incidents (w=0.25)
      - Critical Vulnerabilities Exposure (w=0.25)
      - Critical Asset Exposure (w=0.20)
      - Unresolved Critical Threats (w=0.20)
      - Threat Volume Intensity (w=0.10)
    Returns exact factors, point deductions, and step-by-step mathematical explanation.
    """
    try:
        posture_data = dashboard_service.calculate_security_posture()
        return SecurityPostureResponse(**posture_data)
    except Exception as e:
        log.error(f"Error computing security posture: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error computing security posture.",
        )


@router.get(
    "/executive/summary",
    response_model=ExecutiveSummaryResponse,
    summary="Get Executive Security Briefing Summary",
    status_code=status.HTTP_200_OK,
)
def get_executive_summary_route():
    """
    Retrieve executive-level security briefing metrics, risk distribution,
    threat trends, and top vulnerable assets.
    """
    try:
        summary_data = dashboard_service.get_executive_summary()
        return ExecutiveSummaryResponse(**summary_data)
    except Exception as e:
        log.error(f"Error computing executive summary: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error computing executive summary.",
        )
