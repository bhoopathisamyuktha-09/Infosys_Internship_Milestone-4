"""
services/dashboard_service.py — Milestone 4 Core Aggregation & Analytics Service
================================================================================
Milestone 4: Backend Final Integration, API Completion & Production Hardening

Provides:
  1. Consolidated SOC Dashboard Overview aggregation with dynamic time-window filtering.
  2. Deterministic Security Posture Engine with transparent explainability.
  3. Executive Summary API aggregation.
  4. Security Report generation (JSON and RFC 4180 CSV).
  5. Correlated IOC Intelligence aggregation (real counts, assets, first/last seen).
  6. Vulnerability Intelligence aggregation & advanced filtering.
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from pymongo import ASCENDING, DESCENDING
from pymongo.database import Database

import database.mongo_db as mongo_module

log = logging.getLogger("services.dashboard_service")


def _get_db(db: Optional[Database] = None) -> Database:
    if db is not None:
        return db
    return mongo_module.mongo.get_database()


# ── Time Window Resolution ────────────────────────────────────────────────────

def resolve_time_window(
    db: Database,
    time_range: str = "all",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Resolve start and end timestamps for time-window filtering.
    For seeded datasets, relative filters (24h, 7d, 30d) anchor to the latest
    event timestamp in the database, automatically pivoting to real-time if
    new telemetry has been ingested recently.
    """
    if start_date or end_date:
        s = start_date.strip() if start_date else None
        e = end_date.strip() if end_date else None
        if s and len(s) == 10:
            s = f"{s} 00:00:00"
        if e and len(e) == 10:
            e = f"{e} 23:59:59"
        return s, e

    tr = (time_range or "all").lower().strip()
    if tr == "all":
        return None, None

    # Find reference anchor time: latest event in database
    latest_event = db["security_events"].find_one({}, sort=[("timestamp", -1)])
    if latest_event and latest_event.get("timestamp"):
        try:
            ref_time = pd.to_datetime(latest_event["timestamp"])
        except Exception:
            ref_time = datetime.now(timezone.utc)
    else:
        ref_time = datetime.now(timezone.utc)

    # If recent live data exists within 24h of system clock, use system clock
    now_utc = datetime.now(timezone.utc)
    if (now_utc - pd.to_datetime(ref_time).tz_localize(timezone.utc) if pd.to_datetime(ref_time).tzinfo is None else now_utc - pd.to_datetime(ref_time)) < timedelta(hours=24):
        ref_time = now_utc

    if tr == "24h":
        w_start = ref_time - timedelta(hours=24)
    elif tr == "7d":
        w_start = ref_time - timedelta(days=7)
    elif tr == "30d":
        w_start = ref_time - timedelta(days=30)
    else:
        return None, None

    fmt = "%Y-%m-%d %H:%M:%S"
    return w_start.strftime(fmt), ref_time.strftime(fmt)


# ── 1. Deterministic Security Posture Engine ──────────────────────────────────

def calculate_security_posture(db: Optional[Database] = None) -> Dict[str, Any]:
    """
    Compute deterministic organizational Security Posture on a 0-100 scale.
    Formula: Base (100) - Sum(Weight_i * RiskFactor_i)
    """
    database = _get_db(db)

    # 1. Active Incidents Factor (Weight: 0.25, Max: 25 pts)
    active_incidents = database["incidents"].count_documents({"status": {"$in": ["Open", "Investigating"]}})
    total_incidents = max(1, database["incidents"].count_documents({}))
    crit_active_inc = database["incidents"].count_documents({"status": {"$in": ["Open", "Investigating"]}, "risk_level": "Critical"})
    total_crit_inc = max(1, database["incidents"].count_documents({"risk_level": "Critical"}))
    high_active_inc = database["incidents"].count_documents({"status": {"$in": ["Open", "Investigating"]}, "risk_level": "High"})
    total_high_inc = max(1, database["incidents"].count_documents({"risk_level": "High"}))

    s_inc = min(
        100.0,
        (crit_active_inc / total_crit_inc * 60.0)
        + (high_active_inc / total_high_inc * 30.0)
        + (active_incidents / total_incidents * 10.0),
    )
    d_inc = round(s_inc * 0.25, 1)

    # 2. Critical Vulnerabilities Exposure (Weight: 0.25, Max: 25 pts)
    crit_vulns = database["vulnerabilities"].count_documents({"severity": "Critical"})
    high_vulns = database["vulnerabilities"].count_documents({"severity": "High"})
    tot_vulns = max(1, database["vulnerabilities"].count_documents({}))

    s_vuln = min(100.0, ((crit_vulns / tot_vulns * 70.0) + (high_vulns / tot_vulns * 30.0)) * 2.5)
    d_vuln = round(s_vuln * 0.25, 1)

    # 3. Critical Asset Exposure (Weight: 0.20, Max: 20 pts)
    targeted_assets = database["incidents"].distinct("asset_name")
    tot_targeted_assets = max(1, len(targeted_assets))
    at_risk_assets = len(database["incidents"].distinct("asset_name", {"risk_level": {"$in": ["Critical", "High"]}}))

    s_asset = min(100.0, (at_risk_assets / tot_targeted_assets) * 100.0)
    d_asset = round(s_asset * 0.20, 1)

    # 4. Unresolved Critical Threats (Weight: 0.20, Max: 20 pts)
    tot_crit_events = max(1, database["security_events"].count_documents({"severity": "Critical"}))
    unres_crit_events = database["security_events"].count_documents({
        "severity": "Critical",
        "event_status": {"$in": ["Open", "Detected", "Failed"]},
    })

    s_threat = min(100.0, (unres_crit_events / tot_crit_events) * 100.0)
    d_threat = round(s_threat * 0.20, 1)

    # 5. Threat Volume Intensity (Weight: 0.10, Max: 10 pts)
    tot_events = max(1, database["security_events"].count_documents({}))
    high_crit_events = database["security_events"].count_documents({"severity": {"$in": ["Critical", "High"]}})

    s_vol = min(100.0, (high_crit_events / tot_events) * 100.0)
    d_vol = round(s_vol * 0.10, 1)

    total_deduction = round(d_inc + d_vuln + d_asset + d_threat + d_vol, 1)
    posture_score = max(0, min(100, round(100.0 - total_deduction)))

    if posture_score >= 85:
        label = "Excellent"
    elif posture_score >= 70:
        label = "Good"
    elif posture_score >= 50:
        label = "Needs Attention"
    else:
        label = "Critical"

    explanation = (
        f"Security Posture starts at 100.0. Current telemetry deductions total {total_deduction} points "
        f"across active incidents ({d_inc}), critical vulnerabilities ({d_vuln}), asset exposure ({d_asset}), "
        f"unresolved threats ({d_threat}), and threat volume ({d_vol}), yielding an active score of {posture_score} ({label})."
    )

    factors = {
        "active_incidents": {
            "raw_value": active_incidents,
            "normalized_score": round(s_inc, 1),
            "weight": 0.25,
            "points_deducted": d_inc,
            "explanation": f"{active_incidents:,} active incidents ({crit_active_inc} Critical, {high_active_inc} High).",
        },
        "critical_vulnerabilities": {
            "raw_value": crit_vulns,
            "normalized_score": round(s_vuln, 1),
            "weight": 0.25,
            "points_deducted": d_vuln,
            "explanation": f"{crit_vulns} Critical and {high_vulns} High CVEs recorded across assets.",
        },
        "asset_exposure": {
            "raw_value": at_risk_assets,
            "normalized_score": round(s_asset, 1),
            "weight": 0.20,
            "points_deducted": d_asset,
            "explanation": f"{at_risk_assets} of {tot_targeted_assets} targeted assets are associated with High or Critical incidents.",
        },
        "unresolved_threats": {
            "raw_value": unres_crit_events,
            "normalized_score": round(s_threat, 1),
            "weight": 0.20,
            "points_deducted": d_threat,
            "explanation": f"{unres_crit_events:,} of {tot_crit_events:,} Critical security events remain in unresolved status.",
        },
        "threat_volume": {
            "raw_value": high_crit_events,
            "normalized_score": round(s_vol, 1),
            "weight": 0.10,
            "points_deducted": d_vol,
            "explanation": f"{round(s_vol, 1)}% of ingested telemetry events represent High or Critical severity threats.",
        },
    }

    return {
        "posture_score": posture_score,
        "posture_label": label,
        "baseline": 100.0,
        "total_deduction": total_deduction,
        "contributing_factors": factors,
        "calculation_explanation": explanation,
        "calculated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── 2. Consolidated Dashboard Overview API ───────────────────────────────────

def calculate_dashboard_overview(
    time_range: str = "all",
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: Optional[Database] = None,
) -> Dict[str, Any]:
    """
    Calculate consolidated SOC Dashboard Overview dynamically from MongoDB.
    """
    database = _get_db(db)
    w_start, w_end = resolve_time_window(database, time_range=time_range, start_date=start_date, end_date=end_date)

    # Event query filter
    evt_filter: Dict[str, Any] = {}
    inc_filter: Dict[str, Any] = {}

    if w_start or w_end:
        time_cond: Dict[str, Any] = {}
        if w_start:
            time_cond["$gte"] = w_start
        if w_end:
            time_cond["$lte"] = w_end
        evt_filter["timestamp"] = time_cond
        inc_filter["created_at"] = time_cond

    # 1. Total events in window
    total_events = database["security_events"].count_documents(evt_filter)

    # 2. Detected threats (High or Critical severity, or status Blocked/Detected)
    crit_threats = database["security_events"].count_documents({**evt_filter, "severity": "Critical"})
    high_threats = database["security_events"].count_documents({**evt_filter, "severity": "High"})
    detected_threats = crit_threats + high_threats

    # 3. Threat Severity Distribution
    med_threats = database["security_events"].count_documents({**evt_filter, "severity": "Medium"})
    low_threats = database["security_events"].count_documents({**evt_filter, "severity": "Low"})
    severity_distribution = {
        "Critical": crit_threats,
        "High": high_threats,
        "Medium": med_threats,
        "Low": low_threats,
    }

    # 4. Threat Type Distribution (aggregation pipeline)
    pipe_type = [
        {"$match": evt_filter},
        {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    threat_types = [
        {"threat_type": r["_id"] or "Unknown", "count": r["count"]}
        for r in database["security_events"].aggregate(pipe_type)
    ]

    # 5. Incident metrics
    high_risk_incidents = database["incidents"].count_documents({**inc_filter, "risk_score": {"$gte": 61}})
    active_incidents = database["incidents"].count_documents({**inc_filter, "status": {"$in": ["Open", "Investigating"]}})
    open_incidents = database["incidents"].count_documents({**inc_filter, "status": "Open"})
    investigating_incidents = database["incidents"].count_documents({**inc_filter, "status": "Investigating"})
    resolved_incidents = database["incidents"].count_documents({**inc_filter, "status": "Resolved"})
    false_positive_incidents = database["incidents"].count_documents({**inc_filter, "status": "False Positive"})

    incident_status_distribution = {
        "Open": open_incidents,
        "Investigating": investigating_incidents,
        "Resolved": resolved_incidents,
        "False Positive": false_positive_incidents,
    }

    # 6. Affected Assets in window
    affected_assets_set = set(database["incidents"].distinct("asset_name", inc_filter))
    affected_assets = len([a for a in affected_assets_set if a])

    # 7. Risk Trend (daily average risk score & incident count)
    risk_trend: List[Dict[str, Any]] = []
    pipe_trend = [
        {"$match": inc_filter},
        {
            "$project": {
                "date": {"$substr": ["$created_at", 0, 10]},
                "risk_score": 1,
            }
        },
        {
            "$group": {
                "_id": "$date",
                "count": {"$sum": 1},
                "avg_risk_score": {"$avg": "$risk_score"},
            }
        },
        {"$sort": {"_id": 1}},
        {"$limit": 30},
    ]
    for r in database["incidents"].aggregate(pipe_trend):
        if r.get("_id"):
            risk_trend.append({
                "date": r["_id"],
                "count": r["count"],
                "avg_risk_score": round(r["avg_risk_score"], 1) if r.get("avg_risk_score") is not None else 0,
            })

    # 8. Top Critical / High Incidents
    top_incidents_cursor = (
        database["incidents"]
        .find(inc_filter, {"_id": 0})
        .sort("risk_score", DESCENDING)
        .limit(5)
    )
    top_incidents = list(top_incidents_cursor)

    # 9. Security Posture
    posture = calculate_security_posture(db=database)

    return {
        "time_range": time_range,
        "window_start": w_start,
        "window_end": w_end,
        "total_security_events": total_events,
        "detected_threats": detected_threats,
        "critical_threats": crit_threats,
        "high_risk_incidents": high_risk_incidents,
        "active_incidents": active_incidents,
        "affected_assets": affected_assets,
        "threat_severity_distribution": severity_distribution,
        "threat_type_distribution": threat_types,
        "incident_status_distribution": incident_status_distribution,
        "risk_trend": risk_trend,
        "top_critical_incidents": top_incidents,
        "security_posture": posture,
    }


# ── 3. IOC Intelligence Aggregation ───────────────────────────────────────────

def get_ioc_intelligence(
    severity: Optional[str] = None,
    indicator_type: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    skip: int = 0,
    db: Optional[Database] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """
    Query Threat Intelligence IOCs and correlate with real security events.
    Derives actual threat counts, affected asset lists, real first seen, and last seen.
    """
    database = _get_db(db)
    query: Dict[str, Any] = {}

    if severity and severity != "All":
        query["severity"] = severity
    if indicator_type and indicator_type != "All":
        query["indicator_type"] = indicator_type
    if status and status != "All":
        stat = status.capitalize()
        if stat == "Malicious":
            query["$or"] = [
                {"severity": {"$in": ["Critical", "High"]}},
                {"confidence": {"$in": ["Critical", "High"]}},
            ]
        elif stat == "Suspicious":
            query["$and"] = [
                {"severity": {"$nin": ["Critical", "High"]}},
                {"confidence": {"$nin": ["Critical", "High"]}},
                {"$or": [{"severity": "Medium"}, {"confidence": "Medium"}]},
            ]
        elif stat in ["Benign", "Clean"]:
            query["severity"] = {"$nin": ["Critical", "High", "Medium"]}
            query["confidence"] = {"$nin": ["Critical", "High", "Medium"]}
    if search:
        s = search.strip()
        search_or = [
            {"indicator_value": {"$regex": s, "$options": "i"}},
            {"threat_name": {"$regex": s, "$options": "i"}},
            {"threat_actor": {"$regex": s, "$options": "i"}},
        ]
        if "$or" in query:
            existing_or = query.pop("$or")
            if "$and" in query:
                query["$and"].extend([{"$or": existing_or}, {"$or": search_or}])
            else:
                query["$and"] = [{"$or": existing_or}, {"$or": search_or}]
        else:
            query["$or"] = search_or

    coll = database["threat_intelligence"]
    total = coll.count_documents(query)
    cursor = coll.find(query, {"_id": 0}).skip(skip).limit(limit)
    ioc_docs = list(cursor)

    items: List[Dict[str, Any]] = []
    events_coll = database["security_events"]

    for doc in ioc_docs:
        val = doc.get("indicator_value")
        threat_count = 0
        affected_assets: List[str] = []
        first_seen = None
        last_seen = None

        if val:
            evts_cursor = events_coll.find(
                {"$or": [{"source_ip": val}, {"destination_ip": val}]},
                {"timestamp": 1, "asset_name": 1, "_id": 0},
            ).sort("timestamp", ASCENDING)
            evts = list(evts_cursor)

            threat_count = len(evts)
            if threat_count > 0:
                first_seen = evts[0].get("timestamp")
                last_seen = evts[-1].get("timestamp")
                assets_set = {e.get("asset_name") for e in evts if e.get("asset_name")}
                affected_assets = sorted(list(assets_set))

        # Determine malicious status
        sev = (doc.get("severity") or "").capitalize()
        conf = (doc.get("confidence") or "").capitalize()
        if sev in ["Critical", "High"] or conf in ["Critical", "High"]:
            malicious_status = "Malicious"
        elif sev == "Medium" or conf == "Medium":
            malicious_status = "Suspicious"
        else:
            malicious_status = "Benign"

        items.append({
            "indicator_id": doc.get("indicator_id"),
            "indicator_value": val or "Unknown",
            "indicator_type": doc.get("indicator_type", "IP Address"),
            "malicious_status": malicious_status,
            "threat_count": threat_count,
            "affected_asset_count": len(affected_assets),
            "affected_assets": affected_assets,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "threat_name": doc.get("threat_name"),
            "threat_actor": doc.get("threat_actor"),
            "confidence": doc.get("confidence"),
            "severity": doc.get("severity"),
        })

    return items, total


def get_ioc_summary(db: Optional[Database] = None) -> Dict[str, Any]:
    """Calculate summary metrics for IOC Intelligence."""
    database = _get_db(db)
    coll = database["threat_intelligence"]
    total = coll.count_documents({})

    crit = coll.count_documents({"severity": "Critical"})
    high = coll.count_documents({"severity": "High"})
    med = coll.count_documents({"severity": "Medium"})
    low = coll.count_documents({"severity": "Low"})

    # Type distribution
    type_pipe = [
        {"$group": {"_id": "$indicator_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    type_dist = {r["_id"] or "Unknown": r["count"] for r in coll.aggregate(type_pipe)}

    # Count correlated events matching all malicious IOCs
    malicious_vals = coll.distinct("indicator_value", {"severity": {"$in": ["Critical", "High"]}})
    evts_count = database["security_events"].count_documents({
        "$or": [
            {"source_ip": {"$in": malicious_vals}},
            {"destination_ip": {"$in": malicious_vals}},
        ]
    })
    affected_assets = len(database["security_events"].distinct("asset_name", {
        "$or": [
            {"source_ip": {"$in": malicious_vals}},
            {"destination_ip": {"$in": malicious_vals}},
        ]
    }))

    return {
        "total_indicators": total,
        "malicious_indicators": crit + high,
        "suspicious_indicators": med,
        "correlated_events_total": evts_count,
        "affected_assets_count": affected_assets,
        "type_distribution": type_dist,
        "severity_distribution": {
            "Critical": crit,
            "High": high,
            "Medium": med,
            "Low": low,
        },
    }


# ── 4. Vulnerability Intelligence Aggregation ─────────────────────────────────

def get_vulnerability_summary(db: Optional[Database] = None) -> Dict[str, Any]:
    """Calculate summary metrics for Vulnerability Intelligence."""
    database = _get_db(db)
    coll = database["vulnerabilities"]

    total = coll.count_documents({})
    crit = coll.count_documents({"severity": "Critical"})
    high = coll.count_documents({"severity": "High"})
    med = coll.count_documents({"severity": "Medium"})
    low = coll.count_documents({"severity": "Low"})

    affected_assets = coll.distinct("affected_asset")
    affected_assets_count = len([a for a in affected_assets if a])

    # Top vulnerable assets
    pipe_top = [
        {"$group": {"_id": "$affected_asset", "cve_count": {"$sum": 1}, "max_cvss": {"$max": "$cvss_score"}}},
        {"$sort": {"cve_count": -1}},
        {"$limit": 5},
    ]
    top_assets = [
        {"asset_name": r["_id"] or "Unknown", "cve_count": r["cve_count"], "max_cvss": r["max_cvss"]}
        for r in coll.aggregate(pipe_top)
    ]

    # Status & Patch availability
    open_count = coll.count_documents({"status": "Open"})
    closed_count = coll.count_documents({"status": "Closed"})
    patch_yes = coll.count_documents({"patch_available": {"$in": ["Yes", "yes", True]}})
    patch_no = coll.count_documents({"patch_available": {"$in": ["No", "no", False]}})

    return {
        "total_vulnerabilities": total,
        "critical_cves": crit,
        "high_cves": high,
        "medium_cves": med,
        "low_cves": low,
        "affected_assets_count": affected_assets_count,
        "top_vulnerable_assets": top_assets,
        "status_distribution": {"Open": open_count, "Closed": closed_count},
        "patch_availability": {"Yes": patch_yes, "No": patch_no},
    }


def query_vulnerabilities_advanced(
    severity: Optional[str] = None,
    vuln_status: Optional[str] = None,
    patch_available: Optional[str] = None,
    affected_asset: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    skip: int = 0,
    db: Optional[Database] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Query vulnerabilities with advanced filtering and search."""
    database = _get_db(db)
    query: Dict[str, Any] = {}

    if severity and severity != "All":
        query["severity"] = severity
    if vuln_status and vuln_status != "All":
        query["status"] = vuln_status
    if patch_available and patch_available != "All":
        query["patch_available"] = patch_available
    if affected_asset and affected_asset != "All":
        query["affected_asset"] = affected_asset
    if search:
        s = search.strip()
        query["$or"] = [
            {"cve_id": {"$regex": s, "$options": "i"}},
            {"vulnerability_name": {"$regex": s, "$options": "i"}},
            {"affected_asset": {"$regex": s, "$options": "i"}},
        ]

    coll = database["vulnerabilities"]
    total = coll.count_documents(query)
    cursor = coll.find(query, {"_id": 0}).sort("cvss_score", DESCENDING).skip(skip).limit(limit)
    return list(cursor), total


# ── 5. Executive Summary API ──────────────────────────────────────────────────

def get_executive_summary(db: Optional[Database] = None) -> Dict[str, Any]:
    """Generate dynamic high-level Executive Security Summary."""
    database = _get_db(db)
    overview = calculate_dashboard_overview(time_range="all", db=database)
    vuln_sum = get_vulnerability_summary(db=database)

    # Risk distribution
    inc_coll = database["incidents"]
    risk_distribution = {
        "Critical": inc_coll.count_documents({"risk_level": "Critical"}),
        "High": inc_coll.count_documents({"risk_level": "High"}),
        "Moderate": inc_coll.count_documents({"risk_level": "Moderate"}),
        "Medium": inc_coll.count_documents({"risk_level": "Medium"}),
        "Low": inc_coll.count_documents({"risk_level": "Low"}),
    }

    return {
        "report_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "security_posture": overview["security_posture"],
        "critical_threats": overview["critical_threats"],
        "open_incidents": overview["active_incidents"],
        "critical_vulnerabilities": vuln_sum["critical_cves"],
        "affected_assets": overview["affected_assets"],
        "threat_trend": overview["risk_trend"][:14],
        "risk_distribution": risk_distribution,
        "top_threat_categories": overview["threat_type_distribution"][:5],
        "top_vulnerable_assets": vuln_sum["top_vulnerable_assets"],
    }


# ── 6. Automated Security Report Generation (JSON & RFC 4180 CSV) ─────────────

def generate_security_report_data(db: Optional[Database] = None) -> Dict[str, Any]:
    """Generate complete security report payload from MongoDB."""
    database = _get_db(db)
    now_iso = datetime.now(timezone.utc).isoformat()
    overview = calculate_dashboard_overview(time_range="all", db=database)
    vuln_sum = get_vulnerability_summary(db=database)

    # Top MITRE Techniques
    pipe_mitre = [
        {"$unwind": "$mitre_techniques"},
        {"$group": {"_id": "$mitre_techniques", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]
    top_mitre = [
        {"technique_id": r["_id"], "incident_count": r["count"]}
        for r in database["incidents"].aggregate(pipe_mitre)
    ]

    # Top Vulnerabilities
    top_vulns = list(
        database["vulnerabilities"]
        .find({"severity": {"$in": ["Critical", "High"]}}, {"_id": 0})
        .sort("cvss_score", DESCENDING)
        .limit(5)
    )

    # Detected Attack Chains
    total_attack_chains = database["incidents"].count_documents({"attack_chain_detected": True})
    critical_vulns_count = vuln_sum.get("critical_cves", 0)

    attack_chains_cursor = (
        database["incidents"]
        .find({"attack_chain_detected": True}, {"_id": 0})
        .sort("risk_score", DESCENDING)
        .limit(5)
    )
    attack_chains = [
        {
            "incident_id": doc.get("incident_id"),
            "attack_chain_type": doc.get("attack_chain_type"),
            "asset_name": doc.get("asset_name"),
            "risk_score": doc.get("risk_score"),
            "threat_type": doc.get("threat_type"),
        }
        for doc in attack_chains_cursor
    ]

    # Sample Priority Recommendations
    rec_incident = database["incidents"].find_one({"risk_level": "Critical", "recommendations.0": {"$exists": True}})
    recommendations = rec_incident.get("recommendations", [])[:5] if rec_incident else []

    return {
        "report_title": "SentinelAI — Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics",
        "generated_at": now_iso,
        "total_events": overview["total_security_events"],
        "detected_threats": overview["detected_threats"],
        "critical_incidents": overview["threat_severity_distribution"]["Critical"],
        "high_risk_assets": overview["affected_assets"],
        "security_posture": overview["security_posture"],
        "critical_vulnerabilities": critical_vulns_count,
        "total_attack_chains": total_attack_chains,
        "top_threats": overview["threat_type_distribution"][:5],
        "top_mitre_techniques": top_mitre,
        "top_vulnerabilities": top_vulns,
        "attack_chains": attack_chains,
        "recommendations": recommendations,
    }


def generate_security_report_csv(db: Optional[Database] = None) -> str:
    """
    Generate an RFC 4180 compliant CSV string for the executive security report.
    """
    data = generate_security_report_data(db=db)
    output = io.StringIO()
    writer = csv.writer(output)

    # Title & Metadata
    writer.writerow(["=== SENTINELAI: CREATION OF SECURITY OPERATIONS DASHBOARD FOR THREAT DETECTION WITH RISK MITIGATION ANALYTICS ==="])
    writer.writerow(["Report Title", data["report_title"]])
    writer.writerow(["Generated At", data["generated_at"]])
    writer.writerow([])

    # Executive KPIs
    writer.writerow(["--- 1. EXECUTIVE SECURITY METRICS ---"])
    writer.writerow(["Metric", "Value"])
    writer.writerow(["Total Security Events", data["total_events"]])
    writer.writerow(["Detected Threats", data["detected_threats"]])
    writer.writerow(["Critical Incidents", data["critical_incidents"]])
    writer.writerow(["High-Risk Assets Exposed", data["high_risk_assets"]])
    writer.writerow(["Critical Vulnerabilities", data["critical_vulnerabilities"]])
    writer.writerow(["Total Attack Chains Detected", data["total_attack_chains"]])
    posture = data["security_posture"]
    writer.writerow(["Security Posture Score (0-100)", posture["posture_score"]])
    writer.writerow(["Security Posture Label", posture["posture_label"]])
    writer.writerow(["Total Posture Deduction", posture["total_deduction"]])
    writer.writerow([])

    # Top Threats
    writer.writerow(["--- 2. TOP DETECTED THREAT TYPES ---"])
    writer.writerow(["Threat Type", "Event Count"])
    for t in data["top_threats"]:
        writer.writerow([t.get("threat_type"), t.get("count")])
    writer.writerow([])

    # Top MITRE Techniques
    writer.writerow(["--- 3. TOP MITRE ATT&CK TECHNIQUES ---"])
    writer.writerow(["MITRE Technique ID", "Incident Count"])
    for m in data["top_mitre_techniques"]:
        writer.writerow([m.get("technique_id"), m.get("incident_count")])
    writer.writerow([])

    # Top Vulnerabilities
    writer.writerow(["--- 4. CRITICAL VULNERABILITIES ---"])
    writer.writerow(["CVE ID", "Vulnerability Name", "Severity", "CVSS Score", "Affected Asset", "Patch Available"])
    for v in data["top_vulnerabilities"]:
        writer.writerow([
            v.get("cve_id"),
            v.get("vulnerability_name"),
            v.get("severity"),
            v.get("cvss_score"),
            v.get("affected_asset"),
            v.get("patch_available"),
        ])
    writer.writerow([])

    # Attack Chains
    writer.writerow(["--- 5. IDENTIFIED ATTACK CHAINS ---"])
    writer.writerow(["Incident ID", "Attack Chain Type", "Target Asset", "Risk Score", "Threat Type"])
    for ac in data["attack_chains"]:
        writer.writerow([
            ac.get("incident_id"),
            ac.get("attack_chain_type"),
            ac.get("asset_name"),
            ac.get("risk_score"),
            ac.get("threat_type"),
        ])
    writer.writerow([])

    # Recommendations
    writer.writerow(["--- 6. ADVISORY REMEDIATION RECOMMENDATIONS ---"])
    writer.writerow(["Priority", "Action", "Reason"])
    for r in data["recommendations"]:
        writer.writerow([r.get("priority"), r.get("action"), r.get("reason")])

    return output.getvalue()
