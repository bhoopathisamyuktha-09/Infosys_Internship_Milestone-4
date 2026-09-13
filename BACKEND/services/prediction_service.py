"""
services/prediction_service.py — M2 Prediction Orchestration Service
========================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

This module is the application-level orchestration/business-logic layer.
It connects:
    Incoming Security Event
            ↓
    Temporal History Lookup & Feature Engineering (ml/preprocessing.py)
            ↓
    Production Preprocessor (models/preprocessor.pkl) → X_single (1x16)
            ↓
    Isolation Forest (ml/anomaly_detection.py) → raw IF score + label
            ↓
    Random Forest (ml/classifier.py) → top class + top probability
            ↓
    Hybrid Scorer (services/scoring_service.py) → verdict + confidence + reasons
            ↓
    Prediction Store (database/prediction_store.py) → MongoDB threat_predictions

Architectural Boundaries:
  - Is NOT an HTTP/API layer (no FastAPI, no HTTPException, no Request/Response)
  - Loads models once into memory (cached singletons)
  - Enforces strict temporal causality (history_event.timestamp < incoming_event.timestamp)
  - Uses existing production preprocessor, IF, RF, scorer, and prediction store
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from database.mongo_db import mongo
from database.prediction_store import insert_prediction
from ml.anomaly_detection import predict_single as predict_single_if
from ml.classifier import predict_single as predict_single_rf
from ml.model_loader import get_loaded_models
from ml.preprocessing import engineer_features_single_event
from services.scoring_service import calculate_hybrid_score

logger = logging.getLogger("prediction_service")

# ---------------------------------------------------------------------------
# Default Field Fallbacks (for missing optional event fields)
# ---------------------------------------------------------------------------
DEFAULT_EVENT_FIELDS: Dict[str, Any] = {
    "failed_login_attempts": 0,
    "status_flag": 0,
    "cvss_score": 0.0,
    "severity_score": 0,
    "malware_flag": 0,
    "hour": 12,
    "is_weekend": False,
    "protocol": "TCP",
    "source_country": "India",
    "destination_country": "India",
}


def parse_event_timestamp(ts_val: Any) -> datetime:
    """
    Parse an event timestamp string or datetime into a UTC-aware datetime.

    Accepts ISO-8601 strings, space-separated dates ("YYYY-MM-DD HH:MM:SS"),
    or datetime objects.

    Raises:
        ValueError: if timestamp is missing, empty, or unparseable.
    """
    if ts_val is None or str(ts_val).strip() == "":
        raise ValueError("Missing required 'timestamp' in event payload.")

    if isinstance(ts_val, datetime):
        if ts_val.tzinfo is None:
            return ts_val.replace(tzinfo=timezone.utc)
        return ts_val.astimezone(timezone.utc)

    ts_str = str(ts_val).strip()
    try:
        dt = pd.to_datetime(ts_str)
        if dt.tzinfo is None:
            dt = dt.tz_localize("UTC")
        else:
            dt = dt.tz_convert("UTC")
        return dt.to_pydatetime()
    except Exception as e:
        raise ValueError(f"Invalid timestamp format: '{ts_val}'. Failed to parse.") from e


def _normalize_event_fields(event: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure all required logical feature fields exist with valid defaults."""
    norm_event = dict(event)
    for key, default_val in DEFAULT_EVENT_FIELDS.items():
        if norm_event.get(key) is None:
            norm_event[key] = default_val
    return norm_event


def fetch_historical_events_for_user(
    username: str,
    cutoff_dt: datetime,
    exclude_event_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetch historical events for a user strictly BEFORE cutoff_dt from MongoDB security_events.

    Enforces Temporal Causality (Step 3 & Step 15):
        history_event.timestamp < cutoff_dt

    Excludes any record with event_id == exclude_event_id (prevents self-contamination).

    Args:
        username: Target username
        cutoff_dt: UTC datetime cutoff (incoming event timestamp)
        exclude_event_id: Optional event_id to exclude from history

    Returns:
        List of event dicts from MongoDB
    """
    if not mongo.connected:
        logger.warning("MongoDB is not connected; returning empty history for feature engineering.")
        return []

    try:
        db = mongo.get_database()
        coll = db["security_events"]

        # Fetch candidates for this user
        query: Dict[str, Any] = {"username": str(username)}
        cursor = coll.find(query, {"_id": 0})
        raw_events = list(cursor)

        filtered_history: List[Dict[str, Any]] = []
        for h in raw_events:
            # Exclude current event if present in database
            if exclude_event_id and str(h.get("event_id")) == str(exclude_event_id):
                continue

            h_ts_val = h.get("timestamp")
            if not h_ts_val:
                continue

            try:
                h_dt = parse_event_timestamp(h_ts_val)
                # STRICT TEMPORAL CAUSALITY: history < current cutoff
                if h_dt < cutoff_dt:
                    filtered_history.append(h)
            except Exception:
                continue

        return filtered_history
    except Exception as e:
        logger.error(f"Failed to fetch historical events for user '{username}': {e}")
        return []


def predict_event(
    event: Dict[str, Any],
    history: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Orchestrate full M2 threat prediction pipeline for a single security event.

    Flow:
        1. Validate event_id and timestamp.
        2. Normalize optional event fields to default values if absent.
        3. Build strictly causal historical event list (timestamp < incoming_event.timestamp).
        4. Engineer single-event features (events_per_user, unique_dest, after_hours, impossible_travel).
        5. Transform features using production preprocessor (models/preprocessor.pkl).
        6. Run Isolation Forest -> raw score + label.
        7. Run Random Forest -> predicted threat type + top probability.
        8. Pass to scoring_service -> verdict + final_confidence + reasons.
        9. Persist result via prediction_store -> MongoDB threat_predictions collection.
       10. Return clean serialized prediction result.

    Args:
        event: Incoming security event payload dictionary.
        history: Optional explicit list of prior events. If None, fetched from MongoDB.

    Returns:
        Serialized prediction result dict (conforming to scoring_design.md v1.1.0).

    Raises:
        ValueError: If event_id or timestamp is missing/malformed.
        RuntimeError: If models or database fail.
    """
    # Step 1: Input Validation
    event_id = event.get("event_id")
    if not event_id or str(event_id).strip() == "":
        raise ValueError("Missing required 'event_id' in event payload.")
    event_id = str(event_id).strip()

    raw_ts = event.get("timestamp")
    cutoff_dt = parse_event_timestamp(raw_ts)

    # Step 2: Normalize fields
    norm_event = _normalize_event_fields(event)

    # Step 3: Temporal History Filtering & Causality Enforcement
    username = str(norm_event.get("username", ""))

    if history is not None:
        # Filter provided history strictly: h.timestamp < cutoff_dt AND h.event_id != event_id
        valid_history = []
        for h in history:
            if str(h.get("event_id")) == event_id:
                continue
            h_ts = h.get("timestamp")
            if not h_ts:
                continue
            try:
                h_dt = parse_event_timestamp(h_ts)
                if h_dt < cutoff_dt:
                    valid_history.append(h)
            except Exception:
                continue
    else:
        # Fetch from MongoDB security_events
        valid_history = fetch_historical_events_for_user(
            username=username,
            cutoff_dt=cutoff_dt,
            exclude_event_id=event_id,
        )

    # Step 4: Single Event Feature Engineering
    enriched_event = engineer_features_single_event(norm_event, valid_history)

    # Step 5: Model Singletons & Feature Matrix Transformation
    preprocessor, if_model, clf_model = get_loaded_models()
    X_single = preprocessor.transform_single(enriched_event)  # Shape: (1, 16)

    # Step 6: Isolation Forest Inference
    if_res = predict_single_if(if_model, X_single)
    if_raw_score = float(if_res["anomaly_score"])
    if_anomaly_label = str(if_res["anomaly_label"])

    # Step 7: Random Forest Inference
    rf_res = predict_single_rf(clf_model, X_single)
    rf_predicted_type = str(rf_res["predicted_class"])
    rf_top_prob = float(rf_res["top_probability"])

    # Step 8: Hybrid Scoring Engine
    scoring_result = calculate_hybrid_score(
        event=enriched_event,
        if_raw_score=if_raw_score,
        if_anomaly_label=if_anomaly_label,
        rf_predicted_type=rf_predicted_type,
        rf_top_prob=rf_top_prob,
    )

    # Ensure event_id matches
    scoring_result["event_id"] = event_id

    # Step 9: Persist Prediction via prediction_store
    persisted_prediction = insert_prediction(scoring_result)

    logger.info(
        f"Prediction complete for {event_id}: verdict={persisted_prediction.get('verdict')}, "
        f"confidence={persisted_prediction.get('confidence_score')}, "
        f"threat_type={persisted_prediction.get('predicted_threat_type')}"
    )

    return persisted_prediction
