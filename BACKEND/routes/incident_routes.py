"""
routes/incident_routes.py — Milestone 3 Incident Management & Intelligence API Routes
=====================================================================================
Milestone 3: Risk Prioritization & Security Intelligence

Provides:
  1. GET   /api/v1/incidents
  2. GET   /api/v1/incidents/{incident_id}
  3. PATCH /api/v1/incidents/{incident_id}/status
  4. GET   /api/v1/attack-chains
  5. GET   /api/v1/recommendations/{incident_id}
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status

import database.mongo_db as mongo_module
from risk.enrichment import enrich_threat_intel

from database.incident_repository import (
    add_analyst_feedback,
    get_analyst_feedback,
    get_attack_chains,
    get_incident_by_id,
    get_incident_recommendations,
    list_incidents,
    update_incident_status,
)
from models.m3_schemas import (
    ALLOWED_FEEDBACK_REASONS,
    AnalystFeedbackCreate,
    AnalystFeedbackRecord,
    IncidentDocument,
    IncidentStatusUpdate,
    Recommendation,
    RecommendationResult,
    VALID_INCIDENT_STATUSES,
)

log = logging.getLogger("routes.incident_routes")

router = APIRouter(prefix="/api/v1", tags=["M3 - Incident Intelligence"])


@router.get(
    "/incidents",
    summary="List Prioritized Incidents with Filtering and Pagination",
    status_code=status.HTTP_200_OK,
)
def get_incidents(
    risk_level: Optional[str] = Query(None, description="Filter by risk level (Critical, High, Moderate, Medium, Low)"),
    priority: Optional[str] = Query(None, description="Filter by priority (CRITICAL_IMMEDIATE, HIGH_IMMEDIATE, HIGH, MEDIUM, LOW)"),
    threat_type: Optional[str] = Query(None, description="Filter by threat type"),
    asset_name: Optional[str] = Query(None, description="Filter by affected asset name"),
    department: Optional[str] = Query(None, description="Filter by department (e.g. IT, Finance, Engineering)"),
    mitre_technique: Optional[str] = Query(None, description="Filter by MITRE technique ID (e.g. T1190, T1068, T1110)"),
    cve_id: Optional[str] = Query(None, alias="cve", description="Filter by CVE identifier (e.g. CVE-2024-1045)"),
    ioc_status: Optional[str] = Query(None, description="Filter by IOC status (Malicious, Clean)"),
    severity: Optional[str] = Query(None, description="Filter by threat severity (Critical, High, Medium, Low)"),
    time_range: Optional[str] = Query(None, pattern="^(24h|7d|30d|all)$", description="Filter by relative time window: 24h, 7d, 30d, all"),
    start_date: Optional[str] = Query(None, description="Filter incidents created on or after this timestamp/date"),
    end_date: Optional[str] = Query(None, description="Filter incidents created on or before this timestamp/date"),
    incident_status: Optional[str] = Query(None, alias="status", description="Filter by lifecycle status (Open, Investigating, Resolved, False Positive)"),
    sort_by: str = Query("risk_score", description="Sort field: risk_score, created_at, ml_confidence"),
    sort_order: str = Query("desc", description="Sort direction: desc or asc"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    skip: int = Query(0, ge=0, description="Offset"),
):
    """
    Retrieve prioritized incidents matching optional filter criteria, sorted by risk score descending by default.
    Supports multi-dimensional cross-domain filtering combining severity, asset, CVE, IOC status, and date range.
    """
    try:
        filter_query: Dict[str, Any] = {}
        if isinstance(risk_level, str) and risk_level != "All":
            filter_query["risk_level"] = risk_level.capitalize()
        if isinstance(priority, str) and priority != "All":
            filter_query["priority"] = priority.upper()
        if isinstance(threat_type, str) and threat_type != "All":
            filter_query["threat_type"] = threat_type
        if isinstance(asset_name, str) and asset_name != "All":
            safe_asset = re.escape(asset_name.strip())
            filter_query["asset_name"] = {"$regex": safe_asset, "$options": "i"}
        if isinstance(department, str) and department != "All":
            filter_query["department"] = department
        if isinstance(mitre_technique, str) and mitre_technique != "All":
            filter_query["mitre_techniques"] = mitre_technique
        if isinstance(cve_id, str) and cve_id != "All":
            safe_cve = re.escape(cve_id.strip())
            cve_cond = [
                {"cve_id": {"$regex": safe_cve, "$options": "i"}},
                {"vulnerability_id": {"$regex": safe_cve, "$options": "i"}},
            ]
            if "$and" not in filter_query:
                filter_query["$and"] = []
            filter_query["$and"].append({"$or": cve_cond})
        if isinstance(ioc_status, str) and ioc_status != "All":
            filter_query["ioc_status"] = ioc_status.capitalize()
        if isinstance(severity, str) and severity != "All":
            filter_query["severity"] = severity.capitalize()
        if isinstance(incident_status, str) and incident_status != "All":
            filter_query["status"] = incident_status

        # Date & Time window filtering
        s_date = start_date if isinstance(start_date, str) else None
        e_date = end_date if isinstance(end_date, str) else None
        if isinstance(time_range, str) and time_range.lower() != "all" and not (s_date or e_date):
            from services.dashboard_service import resolve_time_window
            w_start, w_end = resolve_time_window(mongo_module.mongo.get_database(), time_range=time_range)
            s_date = w_start
            e_date = w_end

        if s_date or e_date:
            date_cond: Dict[str, Any] = {}
            if s_date:
                try:
                    from datetime import date as _date
                    sd = _date.fromisoformat(s_date.strip()[:10])
                    date_cond["$gte"] = sd.strftime("%Y-%m-%d 00:00:00")
                except Exception:
                    date_cond["$gte"] = s_date
            if e_date:
                try:
                    from datetime import date as _date
                    ed = _date.fromisoformat(e_date.strip()[:10])
                    date_cond["$lte"] = ed.strftime("%Y-%m-%d 23:59:59")
                except Exception:
                    date_cond["$lte"] = e_date
            filter_query["created_at"] = date_cond

        direction = -1 if (isinstance(sort_order, str) and sort_order.lower() == "desc") else 1
        s_field = sort_by if isinstance(sort_by, str) else "risk_score"
        lim = limit if isinstance(limit, int) else 50
        sk = skip if isinstance(skip, int) else 0
        items, total = list_incidents(
            filter_query=filter_query,
            sort_field=s_field,
            sort_dir=direction,
            limit=lim,
            skip=sk,
        )

        return {
            "total": total,
            "limit": limit,
            "skip": skip,
            "items": items,
        }
    except Exception as e:
        log.error(f"Error listing incidents: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error listing incidents.")


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentDocument,
    summary="Get Complete Incident by ID",
    status_code=status.HTTP_200_OK,
)
def get_incident(incident_id: str):
    """
    Retrieve full details for a single incident including risk breakdown, enrichment,
    reasons, attack chain, and recommendations.
    """
    try:
        incident = get_incident_by_id(incident_id.strip())
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident with ID '{incident_id}' not found.",
            )

        # Ensure risk_score_comparison is present (synthesize for existing documents)
        if not incident.get("risk_score_comparison"):
            score = incident.get("risk_score", 0)
            related_count = incident.get("related_events_count", max(0, len(incident.get("event_ids", [])) - 1))
            chain_detected = bool(incident.get("attack_chain_detected", False))
            chain_type = incident.get("attack_chain_type")
            if chain_detected:
                reason = (
                    f"Detected {chain_type} across {related_count} correlated event(s). "
                    "Correlation increased investigation context and adversary visibility but did not alter the base risk score."
                )
            elif related_count > 0:
                reason = (
                    f"Correlated with {related_count} related security event(s) in a 15-minute sliding window. "
                    "Correlation increased investigation context but did not alter the base risk score."
                )
            else:
                reason = "Correlation increased investigation context but did not alter the base risk score."

            incident["risk_score_comparison"] = {
                "before_correlation": score,
                "after_correlation": score,
                "change": 0,
                "change_reason": reason,
                "related_events_count": related_count,
                "attack_chain_detected": chain_detected,
                "attack_chain_type": chain_type,
                "correlation_keys": ["username", "source_ip", "asset_name"],
                "time_window_minutes": 15,
            }

        # Ensure threat intelligence IOC fields are propagated for existing documents
        if incident.get("ioc_status") == "Malicious" and not incident.get("ioc_value"):
            anchor_id = incident.get("anchor_event_id")
            if anchor_id:
                try:
                    evt = mongo_module.mongo.get_database()["security_events"].find_one({"event_id": anchor_id})
                    if evt:
                        ti = enrich_threat_intel(evt)
                        if ti and ti.found:
                            incident["ioc_value"] = ti.ioc_value
                            incident["ioc_matched_field"] = ti.ioc_matched_field
                            if not incident.get("ioc_type"):
                                incident["ioc_type"] = ti.ioc_type
                            if not incident.get("threat_name"):
                                incident["threat_name"] = ti.threat_name
                            if not incident.get("threat_actor"):
                                incident["threat_actor"] = ti.threat_actor
                            if not incident.get("ioc_confidence"):
                                incident["ioc_confidence"] = ti.confidence
                            if not incident.get("ioc_severity"):
                                incident["ioc_severity"] = ti.severity
                except Exception as ti_err:
                    log.warning(f"Could not backfill IOC fields for {incident_id}: {ti_err}")

        # Ensure status_history is populated
        if not incident.get("status_history"):
            created_ts = incident.get("created_at") or datetime.now(timezone.utc).isoformat()
            history = [
                {
                    "status": "Open",
                    "changed_by": "System",
                    "changed_at": created_ts,
                    "reason": "Incident initialized",
                }
            ]
            cur_status = incident.get("status", "Open")
            if incident.get("feedback"):
                for fb in incident["feedback"]:
                    history.append({
                        "status": "False Positive",
                        "changed_by": fb.get("analyst") or "SOC Analyst",
                        "changed_at": fb.get("created_at") or incident.get("updated_at") or created_ts,
                        "reason": fb.get("reason"),
                    })
            elif cur_status != "Open":
                history.append({
                    "status": cur_status,
                    "changed_by": "SOC Analyst",
                    "changed_at": incident.get("updated_at") or created_ts,
                    "reason": f"Status updated to {cur_status}",
                })
        # Hydrate drill-down fields: source_ip, destination_ip, severity, cve_id, and related_events
        anchor_id = incident.get("anchor_event_id")
        if anchor_id:
            try:
                evt_doc = mongo_module.mongo.get_database()["security_events"].find_one({"event_id": anchor_id}, {"_id": 0})
                if evt_doc:
                    if not incident.get("source_ip"):
                        incident["source_ip"] = evt_doc.get("source_ip")
                    if not incident.get("destination_ip"):
                        incident["destination_ip"] = evt_doc.get("destination_ip")
                    if not incident.get("severity"):
                        incident["severity"] = evt_doc.get("severity")
                    if not incident.get("cve_id"):
                        incident["cve_id"] = evt_doc.get("vulnerability_id")
            except Exception as anchor_err:
                log.warning(f"Could not hydrate anchor event fields for {incident_id}: {anchor_err}")

        if not incident.get("related_events"):
            e_ids = incident.get("event_ids", [])
            if e_ids:
                try:
                    rel_cursor = mongo_module.mongo.get_database()["security_events"].find(
                        {"event_id": {"$in": e_ids}}, {"_id": 0}
                    ).sort("timestamp", 1)
                    incident["related_events"] = list(rel_cursor)
                except Exception as rel_err:
                    log.warning(f"Could not hydrate related_events for {incident_id}: {rel_err}")

        return IncidentDocument(**incident)
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error retrieving incident '{incident_id}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error retrieving incident.")


@router.patch(
    "/incidents/{incident_id}/status",
    response_model=IncidentDocument,
    summary="Update Incident Lifecycle Status",
    status_code=status.HTTP_200_OK,
)
def update_status(incident_id: str, body: IncidentStatusUpdate):
    """
    Update incident status to one of: 'Open', 'Investigating', 'Resolved', 'False Positive'.
    """
    status_val = body.status.strip()
    if status_val not in VALID_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{status_val}'. Allowed: {VALID_INCIDENT_STATUSES}",
        )

    try:
        updated = update_incident_status(
            incident_id.strip(),
            status_val,
            changed_by=body.changed_by or "SOC Analyst",
            reason=body.reason,
        )
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found.",
            )
        return get_incident(incident_id.strip())
    except HTTPException:
        raise
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        log.error(f"Error updating status for '{incident_id}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error updating incident status.")


@router.post(
    "/incidents/{incident_id}/feedback",
    response_model=AnalystFeedbackRecord,
    summary="Submit Structured Analyst Feedback for False Positive",
    status_code=status.HTTP_200_OK,
)
def submit_feedback(incident_id: str, body: AnalystFeedbackCreate):
    """
    Submit structured analyst feedback when marking an incident as False Positive.
    Sets the incident lifecycle status to 'False Positive' and records feedback in MongoDB.
    Persists semantic M4 fields: event_id, prediction, actual_feedback, analyst, timestamp.
    """
    reason_val = body.reason.strip()
    if reason_val not in ALLOWED_FEEDBACK_REASONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid feedback reason '{reason_val}'. Allowed reasons: {ALLOWED_FEEDBACK_REASONS}",
        )

    clean_id = incident_id.strip()
    incident = get_incident_by_id(clean_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{clean_id}' not found.",
        )

    try:
        record = add_analyst_feedback(
            incident_id=clean_id,
            reason=reason_val,
            comment=body.comment.strip() if body.comment else None,
            analyst=body.analyst.strip() if body.analyst else "SOC Analyst",
            event_id=body.event_id or incident.get("anchor_event_id"),
            prediction=body.prediction or incident.get("threat_type"),
            actual_feedback=body.actual_feedback or reason_val,
        )
        return AnalystFeedbackRecord(**record)
    except Exception as e:
        log.error(f"Error submitting analyst feedback for '{clean_id}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error submitting analyst feedback.")


@router.get(
    "/incidents/{incident_id}/feedback",
    response_model=List[AnalystFeedbackRecord],
    summary="Get Analyst Feedback History for an Incident",
    status_code=status.HTTP_200_OK,
)
def get_feedback(incident_id: str):
    """
    Retrieve all structured feedback records submitted for this incident.
    """
    clean_id = incident_id.strip()
    incident = get_incident_by_id(clean_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{clean_id}' not found.",
        )

    try:
        feedback_list = get_analyst_feedback(clean_id)
        return [AnalystFeedbackRecord(**fb) for fb in feedback_list]
    except Exception as e:
        log.error(f"Error retrieving feedback for '{clean_id}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error retrieving feedback.")


@router.get(
    "/feedback",
    response_model=List[AnalystFeedbackRecord],
    summary="Get Global Analyst Feedback Audit Trail",
    status_code=status.HTTP_200_OK,
)
def get_global_feedback(
    limit: int = Query(50, ge=1, le=500, description="Max feedback records"),
    skip: int = Query(0, ge=0, description="Offset"),
):
    """
    Retrieve all structured analyst feedback submissions across incidents and predictions.
    Used for feedback monitoring and offline dataset curation for future model improvement.
    """
    try:
        from database.incident_repository import get_all_analyst_feedback
        items, total = get_all_analyst_feedback(limit=limit, skip=skip)
        return [AnalystFeedbackRecord(**fb) for fb in items]
    except Exception as e:
        log.error(f"Error retrieving global feedback: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error retrieving global feedback.")



@router.get(
    "/attack-chains",
    summary="Get Detected Attack Chains",
    status_code=status.HTTP_200_OK,
)
def get_detected_attack_chains(
    limit: int = Query(50, ge=1, le=500, description="Max attack chains to return"),
    skip: int = Query(0, ge=0, description="Offset"),
):
    """
    Retrieve multi-stage attack chains identified by the correlation engine.
    """
    try:
        items, total = get_attack_chains(limit=limit, skip=skip)
        return {
            "total": total,
            "items": items,
        }
    except Exception as e:
        log.error(f"Error retrieving attack chains: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error retrieving attack chains.")


@router.get(
    "/recommendations/{incident_id}",
    response_model=RecommendationResult,
    summary="Get Advisory Recommendations for an Incident",
    status_code=status.HTTP_200_OK,
)
def get_recommendations_for_incident(incident_id: str):
    """
    Retrieve structured advisory recommendations associated with an incident.
    """
    try:
        incident = get_incident_by_id(incident_id.strip())
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found.",
            )

        raw_recs = incident.get("recommendations", [])
        recs = [Recommendation(**r) for r in raw_recs]
        return RecommendationResult(
            incident_id=incident.get("incident_id"),
            threat_type=incident.get("threat_type", "Unknown"),
            recommendations=recs,
        )
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error retrieving recommendations for '{incident_id}': {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error retrieving recommendations.")
