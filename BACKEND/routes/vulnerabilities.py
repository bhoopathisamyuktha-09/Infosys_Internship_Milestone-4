from fastapi import APIRouter, HTTPException, Query, status
from typing import Optional

from services.data_store import store
from models.schemas import VulnerabilityItem
from models.m4_schemas import PaginatedVulnerabilitiesResponse, VulnerabilitySummaryResponse
from services import dashboard_service

router = APIRouter()


@router.get("/vulnerabilities", response_model=list[VulnerabilityItem], tags=["Vulnerabilities"])
def get_vulnerabilities(
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
):
    """Feeds the frontend's Vulnerabilities page (CVE table), queried live from MongoDB."""
    df = store.query_vulnerabilities(severity=severity, limit=limit)
    if df.empty:
        return []
    return [VulnerabilityItem(**row.to_dict()) for _, row in df.iterrows()]


@router.get(
    "/api/v1/vulnerabilities/summary",
    response_model=VulnerabilitySummaryResponse,
    summary="Get Vulnerability Intelligence Overview & Severity Breakdown",
    tags=["M4 - Vulnerability Intelligence"],
    status_code=status.HTTP_200_OK,
)
def get_vulnerability_summary_route():
    """
    Retrieve aggregate metrics across system CVE vulnerabilities:
    critical/high/medium/low counts, affected assets count, top vulnerable assets,
    status distribution, and patch availability.
    """
    try:
        summary_data = dashboard_service.get_vulnerability_summary()
        return VulnerabilitySummaryResponse(**summary_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving vulnerability summary: {e}",
        )


@router.get(
    "/api/v1/vulnerabilities",
    response_model=PaginatedVulnerabilitiesResponse,
    summary="Query Vulnerabilities with Advanced Filtering & Search",
    tags=["M4 - Vulnerability Intelligence"],
    status_code=status.HTTP_200_OK,
)
def get_vulnerabilities_advanced(
    severity: Optional[str] = Query(None, description="Filter by severity: Critical/High/Medium/Low"),
    vuln_status: Optional[str] = Query(None, alias="status", description="Filter by status: Open/Closed"),
    patch_available: Optional[str] = Query(None, description="Filter by patch availability: Yes/No"),
    affected_asset: Optional[str] = Query(None, description="Filter by affected asset name"),
    search: Optional[str] = Query(None, description="Search CVE ID, vulnerability name, or asset"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    skip: int = Query(0, ge=0, description="Offset"),
):
    """
    Query CVE vulnerability records with multi-dimensional filtering, search, and pagination.
    """
    try:
        items, total = dashboard_service.query_vulnerabilities_advanced(
            severity=severity,
            vuln_status=vuln_status,
            patch_available=patch_available,
            affected_asset=affected_asset,
            search=search,
            limit=limit,
            skip=skip,
        )
        return PaginatedVulnerabilitiesResponse(
            total=total,
            limit=limit,
            skip=skip,
            items=items,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error querying vulnerabilities: {e}",
        )

