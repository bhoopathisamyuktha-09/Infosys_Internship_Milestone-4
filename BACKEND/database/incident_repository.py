"""
database/incident_repository.py — Milestone 3 Incident Persistence Layer
========================================================================
Milestone 3: Risk Prioritization & Security Intelligence

Manages persistence, retrieval, and aggregation for the new `incidents`
MongoDB collection.

Protected boundaries:
  - Does NOT touch or modify `incident_history` or other existing collections.
  - Reuses the global MongoDB connection (`database.mongo_db.mongo`).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pymongo import ASCENDING, DESCENDING, ReturnDocument
from pymongo.collection import Collection
from pymongo.database import Database

import database.mongo_db as mongo_module
from models.m3_schemas import VALID_INCIDENT_STATUSES

log = logging.getLogger("database.incident_repository")

INCIDENTS_COLLECTION = "incidents"


def _get_db(db: Optional[Database] = None) -> Database:
    if db is not None:
        return db
    return mongo_module.mongo.get_database()


def serialize_incident(doc: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Ensure document is JSON serializable and strip MongoDB `_id`."""
    if not doc:
        return None
    d = dict(doc)
    d.pop("_id", None)
    return d


def ensure_incident_indexes(db: Optional[Database] = None) -> None:
    """Create optimized indexes on the `incidents` collection."""
    try:
        database = _get_db(db)
        coll: Collection = database[INCIDENTS_COLLECTION]
        existing = coll.index_information()

        indexes_to_create = [
            ("incident_id_1", [("incident_id", ASCENDING)], True),
            ("risk_score_-1", [("risk_score", DESCENDING)], False),
            ("risk_level_1", [("risk_level", ASCENDING)], False),
            ("priority_1", [("priority", ASCENDING)], False),
            ("status_1", [("status", ASCENDING)], False),
            ("asset_id_1", [("asset_id", ASCENDING)], False),
            ("created_at_-1", [("created_at", DESCENDING)], False),
            ("event_ids_1", [("event_ids", ASCENDING)], False),
            # UNIQUE: one anchor_event_id → one incident (enforced at DB level)
            ("anchor_event_id_1", [("anchor_event_id", ASCENDING)], True),
            ("attack_chain_1", [("attack_chain_detected", ASCENDING)], False),
            ("department_1", [("department", ASCENDING)], False),
            ("mitre_techniques_1", [("mitre_techniques", ASCENDING)], False),
            ("severity_1", [("severity", ASCENDING)], False),
            ("cve_id_1", [("cve_id", ASCENDING)], False),
            ("ioc_status_1", [("ioc_status", ASCENDING)], False),
            ("asset_name_1", [("asset_name", ASCENDING)], False),
        ]

        for name, keys, unique in indexes_to_create:
            if name not in existing:
                coll.create_index(keys, name=name, unique=unique)
                log.info(f"Created index {name} on {INCIDENTS_COLLECTION}")
    except Exception as e:
        log.warning(f"Error creating incident indexes: {e}")


def create_incident(incident_data: Dict[str, Any], db: Optional[Database] = None) -> Dict[str, Any]:
    """Insert an incident document into MongoDB."""
    database = _get_db(db)
    coll: Collection = database[INCIDENTS_COLLECTION]

    doc = dict(incident_data)
    if "created_at" not in doc:
        doc["created_at"] = datetime.now(timezone.utc).isoformat()
    if "status" not in doc:
        doc["status"] = "Open"
    if "status_history" not in doc:
        doc["status_history"] = [
            {
                "status": doc.get("status", "Open"),
                "changed_by": "System",
                "changed_at": doc.get("created_at"),
                "reason": "Incident initialized",
            }
        ]

    coll.insert_one(doc)
    return serialize_incident(doc)  # type: ignore


def get_incident_by_id(incident_id: str, db: Optional[Database] = None) -> Optional[Dict[str, Any]]:
    """Retrieve an incident document by its unique incident_id."""
    database = _get_db(db)
    coll: Collection = database[INCIDENTS_COLLECTION]
    doc = coll.find_one({"incident_id": incident_id})
    return serialize_incident(doc)


def get_incident_by_event_id(event_id: str, db: Optional[Database] = None) -> Optional[Dict[str, Any]]:
    """Retrieve an incident document containing a specific event_id (in event_ids array)."""
    database = _get_db(db)
    coll: Collection = database[INCIDENTS_COLLECTION]
    doc = coll.find_one({"event_ids": event_id})
    return serialize_incident(doc)


def get_incident_by_anchor_event_id(event_id: str, db: Optional[Database] = None) -> Optional[Dict[str, Any]]:
    """Retrieve an incident that was triggered by this specific event (anchor check only)."""
    database = _get_db(db)
    coll: Collection = database[INCIDENTS_COLLECTION]
    doc = coll.find_one({"anchor_event_id": event_id})
    return serialize_incident(doc)


def list_incidents(
    filter_query: Optional[Dict[str, Any]] = None,
    sort_field: str = "risk_score",
    sort_dir: int = -1,
    limit: int = 100,
    skip: int = 0,
    db: Optional[Database] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Query incidents with filtering, sorting, and pagination."""
    database = _get_db(db)
    coll: Collection = database[INCIDENTS_COLLECTION]

    q = filter_query or {}
    total = coll.count_documents(q)
    cursor = coll.find(q).sort(sort_field, sort_dir).skip(skip).limit(limit)
    items = [serialize_incident(doc) for doc in cursor if doc]
    return items, total  # type: ignore


def get_high_risk_incidents(
    min_score: int = 61,
    limit: int = 50,
    skip: int = 0,
    db: Optional[Database] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Return incidents with risk_score >= min_score (High or Critical), sorted DESC.
    Returns (page_items, total_matching_count) for correct pagination metadata.
    """
    database = _get_db(db)
    coll: Collection = database[INCIDENTS_COLLECTION]
    query = {"risk_score": {"$gte": min_score}}
    total = coll.count_documents(query)
    cursor = coll.find(query).sort("risk_score", DESCENDING).skip(skip).limit(limit)
    items = [serialize_incident(doc) for doc in cursor if doc]
    return items, total  # type: ignore


def get_risk_summary(db: Optional[Database] = None) -> Dict[str, Any]:
    """Compute aggregate overview metrics for M3 Risk Summary."""
    database = _get_db(db)
    coll: Collection = database[INCIDENTS_COLLECTION]

    total_incidents = coll.count_documents({})
    critical_count = coll.count_documents({"risk_level": "Critical"})
    high_count = coll.count_documents({"risk_level": "High"})
    moderate_count = coll.count_documents({"risk_level": "Moderate"})
    medium_count = coll.count_documents({"risk_level": "Medium"})
    low_count = coll.count_documents({"risk_level": "Low"})

    open_count = coll.count_documents({"status": "Open"})
    investigating_count = coll.count_documents({"status": "Investigating"})
    resolved_count = coll.count_documents({"status": "Resolved"})
    false_positive_count = coll.count_documents({"status": "False Positive"})

    risk_distribution = {
        "Critical": critical_count,
        "High": high_count,
        "Moderate": moderate_count,
        "Medium": medium_count,
        "Low": low_count,
    }

    # Trend aggregation by date (day)
    trend: List[Dict[str, Any]] = []
    try:
        pipeline = [
            {
                "$project": {
                    "date": {
                        "$substr": ["$created_at", 0, 10]
                    },
                    "risk_level": 1,
                    "risk_score": 1,
                }
            },
            {
                "$group": {
                    "_id": "$date",
                    "count": {"$sum": 1},
                    "avg_risk": {"$avg": "$risk_score"},
                }
            },
            {"$sort": {"_id": 1}},
            {"$limit": 30},
        ]
        agg_results = list(coll.aggregate(pipeline))
        for r in agg_results:
            trend.append({
                "date": r["_id"],
                "count": r["count"],
                "avg_risk_score": round(r["avg_risk"], 1) if r.get("avg_risk") else 0,
            })
    except Exception as e:
        log.warning(f"Failed to aggregate trend: {e}")

    return {
        "total_incidents": total_incidents,
        "critical_count": critical_count,
        "high_count": high_count,
        "moderate_count": moderate_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "open_count": open_count,
        "investigating_count": investigating_count,
        "resolved_count": resolved_count,
        "false_positive_count": false_positive_count,
        "risk_distribution": risk_distribution,
        "trend": trend,
    }


def get_attack_chains(limit: int = 50, skip: int = 0, db: Optional[Database] = None) -> Tuple[List[Dict[str, Any]], int]:
    """Return incidents where attack chains have been detected.
    Returns (page_items, total_matching_count) for correct pagination metadata.
    """
    database = _get_db(db)
    coll: Collection = database[INCIDENTS_COLLECTION]
    query = {"attack_chain_detected": True}
    total = coll.count_documents(query)
    cursor = coll.find(query).sort("risk_score", DESCENDING).skip(skip).limit(limit)
    items = []
    for doc in cursor:
        s = serialize_incident(doc)
        if s:
            ac = s.get("attack_chain") or {}
            items.append({
                "incident_id": s.get("incident_id"),
                "attack_chain_id": ac.get("attack_chain_id") or f"AC-{s.get('incident_id')}",
                "attack_chain_type": s.get("attack_chain_type"),
                "confidence": ac.get("confidence") or "High",
                "attack_chain": s.get("attack_chain"),
                "risk_score": s.get("risk_score"),
                "risk_level": s.get("risk_level"),
                "priority": s.get("priority"),
                "asset_name": s.get("asset_name"),
                "threat_type": s.get("threat_type"),
                "created_at": s.get("created_at"),
            })
    return items, total


def get_incident_recommendations(incident_id: str, db: Optional[Database] = None) -> Optional[List[Dict[str, Any]]]:
    """Retrieve recommendations for a specific incident."""
    database = _get_db(db)
    coll: Collection = database[INCIDENTS_COLLECTION]
    doc = coll.find_one({"incident_id": incident_id}, {"recommendations": 1, "threat_type": 1, "_id": 0})
    if not doc:
        return None
    return doc.get("recommendations", [])


def update_incident_status(
    incident_id: str,
    new_status: str,
    changed_by: str = "SOC Analyst",
    reason: Optional[str] = None,
    db: Optional[Database] = None,
) -> Optional[Dict[str, Any]]:
    """
    Safely update an incident lifecycle status.
    Valid statuses: Open, Investigating, Resolved, False Positive.
    """
    if new_status not in VALID_INCIDENT_STATUSES:
        raise ValueError(f"Invalid status '{new_status}'. Allowed values: {VALID_INCIDENT_STATUSES}")

    database = _get_db(db)
    coll: Collection = database[INCIDENTS_COLLECTION]

    now_iso = datetime.now(timezone.utc).isoformat()
    audit_entry: Dict[str, Any] = {
        "status": new_status,
        "changed_by": changed_by or "SOC Analyst",
        "changed_at": now_iso,
    }
    if reason:
        audit_entry["reason"] = reason

    result = coll.find_one_and_update(
        {"incident_id": incident_id},
        {
            "$set": {"status": new_status, "updated_at": now_iso},
            "$push": {"status_history": audit_entry},
        },
        return_document=ReturnDocument.AFTER,
    )
    return serialize_incident(result)


FEEDBACK_COLLECTION = "analyst_feedback"


def add_analyst_feedback(
    incident_id: str,
    reason: str,
    comment: Optional[str] = None,
    analyst: str = "SOC Analyst",
    event_id: Optional[str] = None,
    prediction: Optional[str] = None,
    actual_feedback: Optional[str] = None,
    db: Optional[Database] = None,
) -> Dict[str, Any]:
    """
    Record structured analyst feedback for an incident and set its status to 'False Positive'.
    Persists semantic M4 fields: event_id, prediction, actual_feedback, analyst, and timestamp.
    """
    database = _get_db(db)
    fb_coll: Collection = database[FEEDBACK_COLLECTION]
    inc_coll: Collection = database[INCIDENTS_COLLECTION]

    now_iso = datetime.now(timezone.utc).isoformat()
    feedback_id = f"FB-{incident_id}-{int(datetime.now(timezone.utc).timestamp())}"

    # Lookup incident to backfill anchor_event_id and threat_type if not explicitly provided
    inc_doc = inc_coll.find_one({"incident_id": incident_id}) or {}
    resolved_event_id = event_id or inc_doc.get("anchor_event_id")
    resolved_prediction = prediction or inc_doc.get("threat_type")
    resolved_feedback = actual_feedback or reason

    record = {
        "feedback_id": feedback_id,
        "incident_id": incident_id,
        "event_id": resolved_event_id,
        "prediction": resolved_prediction,
        "actual_feedback": resolved_feedback,
        "reason": reason,
        "comment": comment,
        "analyst": analyst or "SOC Analyst",
        "timestamp": now_iso,
        "resulting_status": "False Positive",
        "created_at": now_iso,
    }

    fb_coll.insert_one(dict(record))

    audit_entry = {
        "status": "False Positive",
        "changed_by": analyst or "SOC Analyst",
        "changed_at": now_iso,
        "reason": reason,
    }

    # Update incident status to False Positive, attach feedback, and record audit trail
    inc_coll.update_one(
        {"incident_id": incident_id},
        {
            "$set": {"status": "False Positive", "updated_at": now_iso},
            "$push": {
                "feedback": record,
                "status_history": audit_entry,
            },
        },
    )

    record_clean = dict(record)
    record_clean.pop("_id", None)
    return record_clean


def get_analyst_feedback(
    incident_id: str,
    db: Optional[Database] = None,
) -> List[Dict[str, Any]]:
    """Retrieve all feedback entries submitted for an incident."""
    database = _get_db(db)
    fb_coll: Collection = database[FEEDBACK_COLLECTION]
    cursor = fb_coll.find({"incident_id": incident_id}).sort("created_at", -1)
    items = []
    for doc in cursor:
        d = dict(doc)
        d.pop("_id", None)
        items.append(d)
    return items


def get_all_analyst_feedback(
    limit: int = 50,
    skip: int = 0,
    db: Optional[Database] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    """Retrieve all feedback entries across incidents, sorted descending by created_at."""
    database = _get_db(db)
    fb_coll: Collection = database[FEEDBACK_COLLECTION]
    total = fb_coll.count_documents({})
    cursor = fb_coll.find({}).sort("created_at", -1).skip(skip).limit(limit)
    items = []
    for doc in cursor:
        d = dict(doc)
        d.pop("_id", None)
        items.append(d)
    return items, total

