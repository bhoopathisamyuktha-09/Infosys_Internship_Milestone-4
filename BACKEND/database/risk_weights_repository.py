"""
database/risk_weights_repository.py — Milestone 3 Dynamic Risk Weights Storage
==============================================================================
Milestone 3: Risk Prioritization & Security Intelligence

Manages persistence and retrieval of configurable 5-factor risk weights in MongoDB.
Defaults:
  threat_severity     = 0.25 (25%)
  ml_confidence       = 0.25 (25%)
  asset_criticality   = 0.20 (20%)
  vulnerability_cvss  = 0.20 (20%)
  threat_intelligence = 0.10 (10%)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pymongo import ReturnDocument
from pymongo.collection import Collection
from pymongo.database import Database

import database.mongo_db as mongo_module

log = logging.getLogger("database.risk_weights_repository")

RISK_WEIGHTS_COLLECTION = "risk_weights"
ACTIVE_WEIGHTS_DOC_ID = "active_risk_weights"

DEFAULT_RISK_WEIGHTS: Dict[str, float] = {
    "threat_severity": 0.25,
    "ml_confidence": 0.25,
    "asset_criticality": 0.20,
    "vulnerability_cvss": 0.20,
    "threat_intelligence": 0.10,
}


def _get_db(db: Optional[Database] = None) -> Database:
    if db is not None:
        return db
    return mongo_module.mongo.get_database()


def get_active_risk_weights(db: Optional[Database] = None) -> Dict[str, float]:
    """
    Retrieve active 5-factor risk weights from MongoDB.
    Falls back to default weights if unconfigured, DB is offline, or during mock tests.
    """
    try:
        database = _get_db(db)
        coll: Collection = database[RISK_WEIGHTS_COLLECTION]
        doc = coll.find_one({"_id": ACTIVE_WEIGHTS_DOC_ID})
        if doc:
            return {
                "threat_severity": float(doc.get("threat_severity", DEFAULT_RISK_WEIGHTS["threat_severity"])),
                "ml_confidence": float(doc.get("ml_confidence", DEFAULT_RISK_WEIGHTS["ml_confidence"])),
                "asset_criticality": float(doc.get("asset_criticality", DEFAULT_RISK_WEIGHTS["asset_criticality"])),
                "vulnerability_cvss": float(doc.get("vulnerability_cvss", DEFAULT_RISK_WEIGHTS["vulnerability_cvss"])),
                "threat_intelligence": float(doc.get("threat_intelligence", DEFAULT_RISK_WEIGHTS["threat_intelligence"])),
            }
    except Exception as e:
        log.warning(f"Unable to read active risk weights from MongoDB ({e}). Using default weights.")

    return dict(DEFAULT_RISK_WEIGHTS)


def save_risk_weights(weights: Dict[str, float], db: Optional[Database] = None) -> Dict[str, Any]:
    """
    Persist new active risk weights to MongoDB.
    Validation must be performed before calling this function.
    """
    database = _get_db(db)
    coll: Collection = database[RISK_WEIGHTS_COLLECTION]

    now_iso = datetime.now(timezone.utc).isoformat()
    update_doc = {
        "_id": ACTIVE_WEIGHTS_DOC_ID,
        "threat_severity": round(float(weights["threat_severity"]), 4),
        "ml_confidence": round(float(weights["ml_confidence"]), 4),
        "asset_criticality": round(float(weights["asset_criticality"]), 4),
        "vulnerability_cvss": round(float(weights["vulnerability_cvss"]), 4),
        "threat_intelligence": round(float(weights["threat_intelligence"]), 4),
        "updated_at": now_iso,
    }

    coll.find_one_and_update(
        {"_id": ACTIVE_WEIGHTS_DOC_ID},
        {"$set": update_doc},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )

    return {k: v for k, v in update_doc.items() if k != "_id"}


def reset_risk_weights(db: Optional[Database] = None) -> Dict[str, Any]:
    """Reset active risk weights to default 0.25, 0.25, 0.20, 0.20, 0.10."""
    return save_risk_weights(DEFAULT_RISK_WEIGHTS, db=db)
