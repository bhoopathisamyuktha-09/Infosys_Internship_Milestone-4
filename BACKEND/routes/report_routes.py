"""
routes/report_routes.py — Milestone 4 Automated Security Reporting Routes
========================================================================
Milestone 4: Backend Final Integration, API Completion & Production Hardening

Provides:
  1. GET /api/v1/reports/security       - Structured Executive Security Report (JSON)
  2. GET /api/v1/reports/security.csv   - Downloadable Executive Security Report (RFC 4180 CSV)
  3. GET /api/v1/reports/security/csv   - Alias for downloadable CSV report
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Response, status

from models.m4_schemas import SecurityReportResponse
from services import dashboard_service

log = logging.getLogger("routes.report_routes")

router = APIRouter(prefix="/api/v1/reports", tags=["M4 - Security Reporting"])


@router.get(
    "/security",
    response_model=SecurityReportResponse,
    summary="Generate Comprehensive Executive Security Report (JSON)",
    status_code=status.HTTP_200_OK,
)
def get_security_report_json():
    """
    Generate an end-to-end executive security report containing:
      - Report timestamp and executive KPIs
      - Deterministic Security Posture breakdown
      - Top threats, MITRE techniques, and critical vulnerabilities
      - Detected multi-stage attack chains
      - Advisory remediation recommendations
    """
    try:
        report_data = dashboard_service.generate_security_report_data()
        return SecurityReportResponse(**report_data)
    except Exception as e:
        log.error(f"Error generating JSON security report: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error generating security report.",
        )


@router.get(
    "/security.csv",
    summary="Download Executive Security Report (CSV)",
    status_code=status.HTTP_200_OK,
)
@router.get(
    "/security/csv",
    summary="Download Executive Security Report (CSV Alias)",
    status_code=status.HTTP_200_OK,
)
def download_security_report_csv():
    """
    Generate and stream an RFC 4180 compliant CSV export of the executive security report.
    """
    try:
        csv_content = dashboard_service.generate_security_report_csv()
        date_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{date_str}.csv"
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "text/csv; charset=utf-8",
            },
        )
    except Exception as e:
        log.error(f"Error generating CSV security report: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error generating CSV security report.",
        )
