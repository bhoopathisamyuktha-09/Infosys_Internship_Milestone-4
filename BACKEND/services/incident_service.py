"""
services/incident_service.py — Milestone 3 Incident Pipeline Orchestrator
==========================================================================
Milestone 3: Risk Prioritization & Security Intelligence

Orchestrates the complete M3 pipeline:
  M2 Prediction & Event
    ↓
  M3 Enrichment (Asset, CVE, MITRE, Threat Intel)
    ↓
  Event Correlation (15m sliding window)
    ↓
  Attack Chain Detection
    ↓
  Phase 1 Risk Score Engine (0-100 deterministic)
    ↓
  Explainable Reasons & Advisory Recommendations
    ↓
  Incident Persistence in MongoDB (`incidents` collection)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import database.mongo_db as mongo_module
from database.incident_repository import (
    create_incident,
    get_incident_by_anchor_event_id,
    get_incident_by_event_id,
    get_incident_by_id,
)
from models.m3_schemas import (
    AttackChainResult,
    CorrelationResult,
    EnrichmentResult,
    IncidentDocument,
    RiskResult,
)
from risk.correlation import correlate_events, detect_attack_chain
from risk.enrichment import enrich_event
from risk.recommendations import generate_recommendations
from risk.risk_score import calculate_risk

log = logging.getLogger("services.incident_service")

_SEVERITY_NORM_MAP = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
}


def _normalize_event_severity(event: Dict[str, Any]) -> int:
    """Normalize severity to 0-100 scale."""
    sev = event.get("severity")
    if sev and isinstance(sev, str):
        val = _SEVERITY_NORM_MAP.get(sev.lower())
        if val is not None:
            return val

    # Check numeric severity_score (1=Low, 2=Medium, 3=High, 4=Critical)
    sev_score = event.get("severity_score")
    if sev_score is not None:
        try:
            s = int(sev_score)
            if s == 4:
                return 100
            elif s == 3:
                return 75
            elif s == 2:
                return 50
            elif s == 1:
                return 25
            elif 0 <= s <= 100:
                return s
        except (ValueError, TypeError):
            pass

    return 50


def build_incident_reasons(
    enrichment: EnrichmentResult,
    risk_result: RiskResult,
    threat_type: str,
    ml_confidence: float,
    correlation: CorrelationResult,
    attack_chain: AttackChainResult,
) -> List[str]:
    """Generate human-readable explainability bullet points."""
    reasons: List[str] = []

    # 1. Threat & ML model reason
    reasons.append(f"Threat detected: '{threat_type}' with {ml_confidence:.1f}% ML confidence.")

    # 2. Asset reason
    if enrichment.asset and enrichment.asset.found:
        crit = enrichment.asset.criticality or "Unknown"
        reasons.append(f"Target asset '{enrichment.asset.asset_name}' is classified as {crit} criticality.")

    # 3. Vulnerability / CVE reason
    if enrichment.vulnerability and enrichment.vulnerability.found:
        cvss = enrichment.vulnerability.cvss_score
        cve = enrichment.vulnerability.cve_id or "Known Vulnerability"
        reasons.append(f"Associated with {cve} (CVSS score: {cvss}).")

    # 4. Threat intelligence reason
    if enrichment.threat_intel and enrichment.threat_intel.found:
        ioc = enrichment.threat_intel.ioc_value
        matched_via = enrichment.threat_intel.ioc_matched_field or "source_ip"
        conf = enrichment.threat_intel.confidence or "Unknown"
        reasons.append(f"Indicator '{ioc}' (matched via {matched_via}) is active in Threat Intelligence ({conf} confidence).")

    # 5. MITRE ATT&CK reason
    if enrichment.mitre and enrichment.mitre.found:
        tech = enrichment.mitre.technique_name or enrichment.mitre.technique_id
        tactic = enrichment.mitre.tactic or "Attack Tactic"
        reasons.append(f"Aligned with MITRE ATT&CK {enrichment.mitre.technique_id} ({tech} - {tactic}).")

    # 6. Correlation reason
    if correlation.related_events_count > 0:
        reasons.append(
            f"Correlated with {correlation.related_events_count} related security event(s) in a {correlation.time_window_minutes}-minute window."
        )

    # 7. Attack chain reason — use "Detected" not "Confirmed" unless chain is fully validated
    if attack_chain and attack_chain.attack_chain_detected:
        reasons.append(
            f"Detected {attack_chain.attack_chain_type} involving {len(attack_chain.stages)} chronological stages."
        )

    return reasons


def build_risk_comparison(
    anchor_risk_score: int,
    correlation: CorrelationResult,
    attack_chain: AttackChainResult,
) -> Dict[str, Any]:
    """
    Generate explainable risk comparison before vs after correlation.
    Preserves the base 5-factor deterministic risk score without arbitrary score inflation.
    """
    related_count = correlation.related_events_count
    chain_detected = attack_chain.attack_chain_detected
    chain_type = attack_chain.attack_chain_type if chain_detected else None

    if chain_detected:
        reason = (
            f"Detected {chain_type} across {len(attack_chain.stages)} chronological stages "
            f"and {related_count} correlated event(s). Correlation increased investigation context "
            "and adversary attack-progression visibility but did not alter the base risk score."
        )
    elif related_count > 0:
        reason = (
            f"Correlated with {related_count} related security event(s) in a {correlation.time_window_minutes}-minute "
            "window. Correlation increased investigation context but did not alter the base risk score."
        )
    else:
        reason = "Correlation increased investigation context but did not alter the base risk score."

    return {
        "before_correlation": anchor_risk_score,
        "after_correlation": anchor_risk_score,
        "change": 0,
        "change_reason": reason,
        "related_events_count": related_count,
        "attack_chain_detected": chain_detected,
        "attack_chain_type": chain_type,
        "correlation_keys": correlation.correlation_keys,
        "time_window_minutes": correlation.time_window_minutes,
    }


def process_event_to_incident(
    event_id: str,
    db: Any = None,
    persist: bool = True,
) -> Dict[str, Any]:
    """
    Run the end-to-end M3 pipeline for a given event_id.
    If persist=True, saves the generated incident to the `incidents` collection.
    """
    if db is None:
        db = mongo_module.mongo.get_database()

    # 1. Check if an incident already exists with this event as its anchor
    existing_incident = get_incident_by_anchor_event_id(event_id, db=db)
    if existing_incident and persist:
        return existing_incident

    # 2. Fetch security event
    event = db["security_events"].find_one({"event_id": event_id})
    if not event:
        raise ValueError(f"Security event '{event_id}' not found in database.")

    # 3. Fetch M2 prediction if present
    pred = db["threat_predictions"].find_one({"event_id": event_id})

    # Extract prediction / event fields
    threat_type = (
        (pred.get("predicted_threat_type") if pred else None)
        or event.get("event_type")
        or "Unknown Threat"
    )

    ml_confidence = float(
        (pred.get("confidence_score") if pred else None)
        or event.get("threat_confidence")
        or 50.0
    )

    anomaly_score = float(
        (pred.get("anomaly_score") if pred else None)
        or 0.0
    )

    threat_severity_norm = _normalize_event_severity(event)

    # 4. M3 Enrichment
    enrichment = enrich_event(event)

    # 5. Correlation
    correlation = correlate_events(event, db=db)

    # 6. Attack Chain Detection
    raw_correlated_events = []
    if correlation.related_event_ids:
        raw_correlated_events = list(
            db["security_events"].find({"event_id": {"$in": correlation.related_event_ids}})
        )
    attack_chain = detect_attack_chain(event, raw_correlated_events)

    # 7. Phase 1 Risk Engine Calculation
    risk_result = calculate_risk(
        enrichment=enrichment,
        ml_confidence=int(round(ml_confidence)),
        threat_severity=threat_severity_norm,
    )

    # 8. Reasons & Recommendations
    reasons = build_incident_reasons(
        enrichment=enrichment,
        risk_result=risk_result,
        threat_type=threat_type,
        ml_confidence=ml_confidence,
        correlation=correlation,
        attack_chain=attack_chain,
    )

    recommendations = generate_recommendations(
        threat_type=threat_type,
        attack_chain=attack_chain,
        enrichment=enrichment,
    )

    # Risk Score Comparison (Before vs After Correlation)
    risk_comparison = build_risk_comparison(
        anchor_risk_score=risk_result.score,
        correlation=correlation,
        attack_chain=attack_chain,
    )

    # 9. Formulate Incident Document
    # Deterministic incident ID: INC-{num} based on event_id suffix or index
    num_part = "".join(filter(str.isdigit, event_id))
    if num_part:
        incident_id = f"INC-{int(num_part):06d}"
    else:
        incident_id = f"INC-{event_id}"

    event_ids = [event_id]
    for eid in correlation.related_event_ids:
        if eid not in event_ids:
            event_ids.append(eid)

    mitre_techs = []
    if enrichment.mitre and enrichment.mitre.technique_id:
        mitre_techs.append(enrichment.mitre.technique_id)
    elif event.get("technique_id"):
        mitre_techs.append(event["technique_id"])

    created_ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()

    # Determine threat intel values from enrichment
    _ti = enrichment.threat_intel if enrichment.threat_intel and enrichment.threat_intel.found else None

    if attack_chain.attack_chain_detected:
        attack_chain.attack_chain_id = f"AC-{incident_id}"

    incident_data = {
        "incident_id": incident_id,
        "anchor_event_id": event_id,
        "event_ids": event_ids,
        "threat_type": threat_type,
        "risk_score": risk_result.score,
        "risk_level": risk_result.level,
        "priority": risk_result.priority,
        "asset_id": (enrichment.asset.asset_id if enrichment.asset and enrichment.asset.found else None) or event.get("asset_id"),
        "asset_name": enrichment.asset.asset_name or event.get("asset_name"),
        "department": (enrichment.asset.department if enrichment.asset and enrichment.asset.found else None) or event.get("department"),
        "affected_user": event.get("username"),
        "source_ip": event.get("source_ip"),
        "destination_ip": event.get("destination_ip"),
        "severity": event.get("severity"),
        "ml_confidence": round(ml_confidence, 2),
        "anomaly_score": round(anomaly_score, 4),
        "cve_id": (enrichment.vulnerability.cve_id if enrichment.vulnerability and enrichment.vulnerability.found else None) or event.get("vulnerability_id"),
        "cvss_score": enrichment.vulnerability.cvss_score,
        "ioc_status": "Malicious" if _ti else "Clean",
        "ioc_value": _ti.ioc_value if _ti else None,
        "ioc_matched_field": _ti.ioc_matched_field if _ti else None,
        "ioc_type": _ti.ioc_type if _ti else None,
        "ioc_confidence": _ti.confidence if _ti else None,
        "ioc_severity": _ti.severity if _ti else None,
        "threat_name": _ti.threat_name if _ti else None,
        "threat_actor": _ti.threat_actor if _ti else None,  # Actual threat_actor from DB
        "mitre_techniques": mitre_techs,
        "related_events_count": correlation.related_events_count,
        "attack_chain_detected": attack_chain.attack_chain_detected,
        "attack_chain_type": attack_chain.attack_chain_type if attack_chain.attack_chain_detected else None,
        "attack_chain": attack_chain.model_dump() if attack_chain.attack_chain_detected else None,
        "risk_breakdown": risk_result.breakdown.model_dump(),
        "risk_score_comparison": risk_comparison,
        "reasons": reasons,
        "recommendations": [r.model_dump() for r in recommendations],
        "status": "Open",
        "status_history": [
            {
                "status": "Open",
                "changed_by": "System",
                "changed_at": created_ts,
                "reason": "Incident initialized",
            }
        ],
        "created_at": created_ts,
    }

    if persist:
        # Save to database
        return create_incident(incident_data, db=db)

    return incident_data

