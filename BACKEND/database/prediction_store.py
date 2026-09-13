"""
database/prediction_store.py — M2 Threat Prediction Persistence Layer
========================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

This module handles persistence and retrieval of M2 threat prediction documents
in MongoDB (collection: threat_predictions).

Reuses the existing M1 MongoDatabase connection instance (`database.mongo_db.mongo`).

Protected Boundaries:
  - Does NOT load ML models or perform inference
  - Does NOT call Isolation Forest, Random Forest, or scoring_service
  - Does NOT handle FastAPI HTTP requests or routes directly
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database

from database.mongo_db import mongo

logger = logging.getLogger("prediction_store")

COLLECTION_NAME = "threat_predictions"

# Default Model Metadata Versions (matching scoring_design.md v1.1.0 / Phase 6A)
DEFAULT_MODEL_METADATA = {
    "preprocessor_version": "1.5.0",
    "if_model_version": "1.0.0-phase3",
    "clf_model_version": "1.1.0-phase4.6",
    "scoring_design_version": "1.1.0",
}

REQUIRED_PREDICTION_FIELDS = {
    "event_id",
    "verdict",
    "confidence_score",
    "predicted_threat_type",
    "rf_top_probability",
    "rf_confidence_note",
    "anomaly_label",
    "anomaly_score",
    "anomaly_score_raw",
    "rule_score",
    "triggered_rules",
    "reasons",
    "model_signals",
}


def serialize_prediction(doc: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure document is clean and serializable (strips MongoDB _id).
    """
    clean_doc = dict(doc)
    clean_doc.pop("_id", None)
    return clean_doc


class PredictionStore:
    """MongoDB Data Access Layer for M2 Threat Predictions."""

    def get_collection(self) -> Collection:
        """Get the threat_predictions collection from MongoDB."""
        db: Database = mongo.get_database()
        return db[COLLECTION_NAME]

    def ensure_indexes(self) -> None:
        """
        Create all 5 non-unique indexes specified in Phase 6A design contract.
        Idempotent (safe to call on startup).
        """
        coll = self.get_collection()

        indexes = [
            # 1. Compound index for retrieving latest prediction by event_id
            ([("event_id", ASCENDING), ("prediction_timestamp", DESCENDING)], {}),
            # 2. Single index for chronological feed
            ([("prediction_timestamp", DESCENDING)], {}),
            # 3. Compound index for filtering feed by verdict
            ([("verdict", ASCENDING), ("prediction_timestamp", DESCENDING)], {}),
            # 4. Single index for threat summary aggregations
            ([("predicted_threat_type", ASCENDING)], {}),
            # 5. Compound index for filtering anomalies
            ([("anomaly_label", ASCENDING), ("prediction_timestamp", DESCENDING)], {}),
        ]

        for keys, kwargs in indexes:
            coll.create_index(keys, **kwargs)

        logger.info(f"Ensured {len(indexes)} non-unique indexes on collection '{COLLECTION_NAME}'.")

    def insert_prediction(self, prediction_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and insert a threat prediction document into MongoDB.

        Args:
            prediction_dict: Scoring result payload

        Returns:
            Serialized prediction dict without MongoDB _id

        Raises:
            ValueError: If required fields are missing
            RuntimeError: If MongoDB is disconnected
        """
        # Validate required fields
        missing = REQUIRED_PREDICTION_FIELDS - set(prediction_dict.keys())
        if missing:
            raise ValueError(f"Cannot insert prediction: missing required fields: {sorted(missing)}")

        doc = dict(prediction_dict)

        event_id = str(doc["event_id"])
        now_utc = datetime.now(timezone.utc)

        # Generate prediction_id if missing
        if not doc.get("prediction_id"):
            epoch_ms = int(now_utc.timestamp() * 1000)
            doc["prediction_id"] = f"PRED_{event_id}_{epoch_ms}"

        # Generate prediction_timestamp if missing
        if not doc.get("prediction_timestamp"):
            doc["prediction_timestamp"] = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Attach model_metadata if missing
        if not doc.get("model_metadata"):
            doc["model_metadata"] = dict(DEFAULT_MODEL_METADATA)

        coll = self.get_collection()
        coll.insert_one(doc)

        return serialize_prediction(doc)

    def get_prediction_by_id(self, prediction_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a prediction by its prediction_id.

        Args:
            prediction_id: Deterministic prediction ID string

        Returns:
            Serialized prediction dict or None
        """
        coll = self.get_collection()
        doc = coll.find_one({"prediction_id": str(prediction_id)}, {"_id": 0})
        return serialize_prediction(doc) if doc else None

    def get_latest_prediction_by_event_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve the latest prediction for a given event_id.

        Args:
            event_id: Event ID string

        Returns:
            Latest prediction dict or None
        """
        coll = self.get_collection()
        cursor = coll.find({"event_id": str(event_id)}, {"_id": 0}).sort("prediction_timestamp", DESCENDING).limit(1)
        results = list(cursor)
        return serialize_prediction(results[0]) if results else None

    def list_predictions(
        self,
        verdict: Optional[str] = None,
        threat_type: Optional[str] = None,
        event_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        skip: int = 0,
    ) -> Dict[str, Any]:
        """
        Query predictions feed with optional filtering, newest first.

        Args:
            verdict: Optional filter ("Normal", "Suspicious", "Critical")
            threat_type: Optional filter by predicted_threat_type
            event_id: Optional search filter by event_id
            severity: Optional filter by original severity score
            limit: Page size (1 to 1000)
            skip: Offset (>= 0)

        Returns:
            List of serialized prediction dicts
        """
        safe_limit = max(1, min(int(limit), 1000))
        safe_skip = max(0, int(skip))

        query: Dict[str, Any] = {}
        if verdict and verdict != "All":
            query["verdict"] = verdict
        if threat_type and threat_type != "All":
            query["predicted_threat_type"] = threat_type
        if event_id and event_id.strip():
            query["event_id"] = {"$regex": event_id.strip(), "$options": "i"}

        coll = self.get_collection()
        pipeline = []
        if query:
            pipeline.append({"$match": query})

        pipeline.extend([
            {"$sort": {"prediction_timestamp": DESCENDING}},
            {
                "$lookup": {
                    "from": "security_events",
                    "localField": "event_id",
                    "foreignField": "event_id",
                    "as": "source_event",
                }
            },
            {"$unwind": {"path": "$source_event", "preserveNullAndEmptyArrays": True}},
            {
                "$addFields": {
                    "original_event_type": "$source_event.event_type",
                    "original_severity": "$source_event.severity_score"
                }
            }
        ])

        # If filtering by severity, apply a second match after the lookup
        if severity and severity != "All":
            # Map string severities like "High" to their numeric M1 values if needed
            # 1="Low", 2="Medium", 3="High", 4="Critical"
            sev_map = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
            sev_val = sev_map.get(severity)
            if sev_val is not None:
                pipeline.append({"$match": {"original_severity": sev_val}})
            else:
                try:
                    pipeline.append({"$match": {"original_severity": int(severity)}})
                except ValueError:
                    pass

        # Apply skip/limit after all filtering is done using facet to get total
        pipeline.extend([
            {
                "$facet": {
                    "metadata": [{"$count": "total"}],
                    "data": [
                        {"$skip": safe_skip},
                        {"$limit": safe_limit},
                        {
                            "$project": {
                                "source_event": 0,
                                "_id": 0
                            }
                        }
                    ]
                }
            }
        ])
        
        cursor = list(coll.aggregate(pipeline))
        if not cursor:
            return {"items": [], "total": 0}
            
        result = cursor[0]
        total_count = result["metadata"][0]["total"] if result["metadata"] else 0
        items = [serialize_prediction(doc) for doc in result["data"]]
        return {"items": items, "total": total_count}

    def list_anomalies(
        self,
        limit: int = 100,
        skip: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Query high-risk predictions (final verdict IN ['Suspicious', 'Critical']), newest first.

        Semantics:
          /anomalies = predictions whose final HYBRID THREAT VERDICT is Suspicious or Critical.

        Distinction:
          - anomaly_label  : Isolation Forest raw signal ('Suspicious' = IF anomaly, 'Normal' = IF normal)
          - verdict        : Final hybrid threat assessment ('Normal', 'Suspicious', 'Critical')
          - /anomalies     : Final high-risk prediction feed filtered on verdict only

        Args:
            limit: Page size (1 to 1000)
            skip: Offset (>= 0)

        Returns:
            List of serialized prediction dicts
        """
        safe_limit = max(1, min(int(limit), 1000))
        safe_skip = max(0, int(skip))

        coll = self.get_collection()
        cursor = (
            coll.find(
                {"verdict": {"$in": ["Suspicious", "Critical"]}},
                {"_id": 0},
            )
            .sort("prediction_timestamp", DESCENDING)
            .skip(safe_skip)
            .limit(safe_limit)
        )
        return [serialize_prediction(doc) for doc in cursor]

    def get_threat_summary(self) -> List[Dict[str, Any]]:
        """
        Aggregate predictions grouped by predicted_threat_type.

        Returns:
            List of dicts: [{"threat_type": str, "count": int, "avg_confidence": float}, ...]
        """
        coll = self.get_collection()
        pipeline = [
            {
                "$group": {
                    "_id": "$predicted_threat_type",
                    "count": {"$sum": 1},
                    "avg_confidence": {"$avg": "$confidence_score"},
                }
            },
            {"$sort": {"count": -1}},
            {
                "$project": {
                    "_id": 0,
                    "threat_type": "$_id",
                    "count": 1,
                    "avg_confidence": 1,
                }
            },
        ]
        results = list(coll.aggregate(pipeline))
        for r in results:
            if r.get("avg_confidence") is not None:
                r["avg_confidence"] = round(float(r["avg_confidence"]), 1)
            else:
                r["avg_confidence"] = 0.0
        return results

    def get_prediction_statistics(self) -> Dict[str, Any]:
        """
        Calculate prediction-distribution statistics (useful for /model-performance).

        Note: These are prediction-distribution metrics, NOT ground-truth accuracy.

        Returns:
            Dict containing counts, rates, and average confidence.
        """
        coll = self.get_collection()
        total = coll.count_documents({})

        if total == 0:
            return {
                "total_predictions": 0,
                "normal_count": 0,
                "suspicious_count": 0,
                "critical_count": 0,
                "anomaly_count": 0,
                "anomaly_rate": 0.0,
                "average_confidence": 0.0,
            }

        normal = coll.count_documents({"verdict": "Normal"})
        suspicious = coll.count_documents({"verdict": "Suspicious"})
        critical = coll.count_documents({"verdict": "Critical"})
        anomalies = coll.count_documents({"anomaly_label": "Suspicious"})

        avg_pipeline = [
            {"$group": {"_id": None, "avg_conf": {"$avg": "$confidence_score"}}}
        ]
        avg_res = list(coll.aggregate(avg_pipeline))
        avg_conf = round(float(avg_res[0]["avg_conf"]), 1) if avg_res else 0.0

        return {
            "total_predictions": total,
            "normal_count": normal,
            "suspicious_count": suspicious,
            "critical_count": critical,
            "anomaly_count": anomalies,
            "anomaly_rate": round(float(anomalies / total), 4),
            "average_confidence": avg_conf,
        }

    def get_prediction_trend(self) -> List[Dict[str, Any]]:
        """
        Aggregate prediction volume and threat breakdown by original security-event date.
        Uses $lookup to join threat_predictions with security_events
        to obtain the authoritative source-event timestamp.
        Returns [{"date": "YYYY-MM-DD", "count": int, "suspicious": int, "critical": int, "normal": int}, ...] sorted chronologically.
        """
        coll = self.get_collection()
        pipeline = [
            # Join with security_events to get the authoritative timestamp
            {
                "$lookup": {
                    "from": "security_events",
                    "localField": "event_id",
                    "foreignField": "event_id",
                    "as": "source_event",
                }
            },
            # Unwind the joined array (1:1 relationship)
            {"$unwind": {"path": "$source_event", "preserveNullAndEmptyArrays": True}},
            # Extract the date portion from the source event timestamp
            # security_events.timestamp format is "YYYY-MM-DD HH:MM:SS"
            {
                "$project": {
                    "event_date": {
                        "$substr": [
                            {"$ifNull": ["$source_event.timestamp", "$prediction_timestamp"]},
                            0,
                            10,
                        ]
                    },
                    "verdict": 1,
                    "anomaly_label": 1,
                }
            },
            # Group by date and calculate verdict breakdowns
            {
                "$group": {
                    "_id": "$event_date",
                    "count": {"$sum": 1},
                    "normal": {"$sum": {"$cond": [{"$eq": ["$verdict", "Normal"]}, 1, 0]}},
                    "suspicious": {"$sum": {"$cond": [{"$eq": ["$verdict", "Suspicious"]}, 1, 0]}},
                    "critical": {"$sum": {"$cond": [{"$eq": ["$verdict", "Critical"]}, 1, 0]}},
                    "anomalies": {"$sum": {"$cond": [{"$eq": ["$anomaly_label", "Suspicious"]}, 1, 0]}},
                }
            },
            # Sort chronologically
            {"$sort": {"_id": 1}},
            # Rename _id to date
            {
                "$project": {
                    "_id": 0,
                    "date": "$_id",
                    "count": 1,
                    "normal": 1,
                    "suspicious": 1,
                    "critical": 1,
                    "anomalies": 1,
                }
            },
        ]
        return list(coll.aggregate(pipeline))

    def get_top_risk_predictions(self, limit: int = 3) -> List[Dict[str, Any]]:
        """
        Return top N predictions sorted by confidence_score DESC.
        """
        safe_limit = max(1, min(int(limit), 50))
        coll = self.get_collection()
        cursor = (
            coll.find({}, {"_id": 0})
            .sort("confidence_score", DESCENDING)
            .limit(safe_limit)
        )
        return [serialize_prediction(doc) for doc in cursor]


# Single shared instance
prediction_store = PredictionStore()

# Module-level functional wrappers for convenience
ensure_indexes = prediction_store.ensure_indexes
insert_prediction = prediction_store.insert_prediction
get_prediction_by_id = prediction_store.get_prediction_by_id
get_latest_prediction_by_event_id = prediction_store.get_latest_prediction_by_event_id
list_predictions = prediction_store.list_predictions
list_anomalies = prediction_store.list_anomalies
get_threat_summary = prediction_store.get_threat_summary
get_prediction_statistics = prediction_store.get_prediction_statistics
get_prediction_trend = prediction_store.get_prediction_trend
get_top_risk_predictions = prediction_store.get_top_risk_predictions
