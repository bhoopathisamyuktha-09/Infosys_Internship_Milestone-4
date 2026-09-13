from fastapi import APIRouter, HTTPException, Query, status
from typing import Optional

from services.data_store import store
from models.schemas import ThreatIntelItem
from models.m4_schemas import IocAggregatedResponse, IocSummaryResponse
from services import dashboard_service

router = APIRouter()


@router.get("/threat-intel", response_model=list[ThreatIntelItem], tags=["Threat Intelligence"])
def get_threat_intel(
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
):
    """Feeds the frontend's Threat Intelligence page (IOC table), queried live from MongoDB."""
    df = store.query_threat_intel(severity=severity, limit=limit)
    if df.empty:
        return []
    return [ThreatIntelItem(**row.to_dict()) for _, row in df.iterrows()]


@router.get(
    "/api/v1/threat-intel/indicators",
    response_model=IocAggregatedResponse,
    summary="Get Correlated Threat Intelligence Indicators (M4 IOC Panel)",
    tags=["M4 - Threat Intelligence"],
    status_code=status.HTTP_200_OK,
)
def get_aggregated_ioc_indicators(
    severity: Optional[str] = Query(None, description="Filter by IOC severity: Critical/High/Medium/Low"),
    indicator_type: Optional[str] = Query(None, description="Filter by indicator type: IP Address, etc."),
    status: Optional[str] = Query(None, description="Filter by status: Malicious, Suspicious, Benign"),
    search: Optional[str] = Query(None, description="Search indicator value, threat name, or actor"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    skip: int = Query(0, ge=0, description="Offset"),
):
    """
    Retrieve Threat Intelligence indicators dynamically correlated with real security telemetry.
    Calculates threat counts, affected asset lists, real first seen, and real last seen timestamps.
    """
    try:
        items, total = dashboard_service.get_ioc_intelligence(
            severity=severity,
            indicator_type=indicator_type,
            status=status,
            search=search,
            limit=limit,
            skip=skip,
        )
        return IocAggregatedResponse(
            total=total,
            limit=limit,
            skip=skip,
            items=items,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving IOC intelligence: {e}",
        )


@router.get(
    "/api/v1/threat-intel/summary",
    response_model=IocSummaryResponse,
    summary="Get IOC Overview & Correlation Summary Metrics",
    tags=["M4 - Threat Intelligence"],
    status_code=status.HTTP_200_OK,
)
def get_ioc_summary_route():
    """
    Retrieve aggregate metrics across threat intelligence indicators:
    total indicators, malicious/suspicious counts, correlated event counts, and affected assets.
    """
    try:
        summary_data = dashboard_service.get_ioc_summary()
        return IocSummaryResponse(**summary_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving IOC summary: {e}",
        )

