"""
routes/prediction_routes.py — FastAPI Prediction APIs (Milestone 2)
===================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

This module implements the 8 REST API endpoints for Milestone 2:
  1. POST /predict                      - Compute ML threat prediction for an event
  2. GET  /predictions                  - Query prediction history feed (with filtering)
  3. GET  /prediction-trend             - Daily historical prediction volume by source event date
  4. GET  /top-predictions              - Retrieve top N predictions sorted by confidence_score DESC
  5. GET  /predictions/{prediction_id}   - Retrieve single prediction by ID
  6. GET  /anomalies                    - Query predictions flagged as anomalous
  7. GET  /model-performance            - Return offline evaluation metrics & distribution stats
  8. GET  /threat-summary               - Return threat-type aggregations (with backend percentage)

Architectural Boundary:
  - THIN API layer delegating to prediction_service and prediction_store
  - NO ML library imports
  - NO ML inference or scoring math
  - NO direct database driver calls
  - NO model fitting or training
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from database import prediction_store
from database.mongo_db import mongo
from models.schemas import (
    PaginatedPredictionResponse,
    PredictionRequest,
    PredictionResponse,
    ThreatSummaryItem,
)
from services import prediction_service
from utils.logger import get_logger

log = get_logger("prediction_routes")

router = APIRouter()


# ---------------------------------------------------------------------------
# Endpoint 1: POST /predict
# ---------------------------------------------------------------------------
@router.post(
    "/predict",
    response_model=PredictionResponse,
    status_code=status.HTTP_200_OK,
    summary="Compute Threat Prediction for Event",
)
def predict_event(payload: PredictionRequest):
    """
    Compute ML threat prediction for a single security event.
    """
    try:
        event_dict = payload.model_dump()
        result = prediction_service.predict_event(event_dict)
        return result
    except ValueError as ve:
        log.warning(f"Validation error in POST /predict: {ve}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(ve),
        )
    except Exception as e:
        log.error(f"Unhandled error in POST /predict: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to compute prediction",
        )


# ---------------------------------------------------------------------------
# Endpoint 2: GET /predictions
# ---------------------------------------------------------------------------
@router.get(
    "/predictions",
    response_model=PaginatedPredictionResponse,
    status_code=status.HTTP_200_OK,
    summary="Query Prediction History Feed",
)
def list_predictions(
    verdict: Optional[str] = Query(
        None, description="Filter by verdict: Normal | Suspicious | Critical"
    ),
    threat_type: Optional[str] = Query(
        None, description="Filter by predicted threat type"
    ),
    event_id: Optional[str] = Query(
        None, description="Search filter by security event ID"
    ),
    severity: Optional[str] = Query(
        None, description="Filter by original severity score"
    ),
    limit: int = Query(
        100, ge=1, le=100, description="Max predictions to return (1-100)"
    ),
    skip: int = Query(0, ge=0, description="Offset for pagination"),
):
    """
    Return prediction history feed sorted newest first, with optional filtering.
    """
    try:
        results = prediction_store.list_predictions(
            verdict=verdict, threat_type=threat_type, event_id=event_id, severity=severity, limit=limit, skip=skip
        )
        return results
    except Exception as e:
        log.error(f"Error in GET /predictions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve predictions history",
        )


# ---------------------------------------------------------------------------
# Endpoint: GET /prediction-trend
# ---------------------------------------------------------------------------
@router.get(
    "/prediction-trend",
    status_code=status.HTTP_200_OK,
    summary="Return Daily Prediction Volume by Source Event Date",
)
def get_prediction_trend():
    """
    Return daily prediction-volume buckets aggregated by the original
    security-event timestamp (via $lookup), sorted chronologically.
    """
    try:
        trend = prediction_store.get_prediction_trend()
        return trend
    except Exception as e:
        log.error(f"Error in GET /prediction-trend: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve prediction trend",
        )


# ---------------------------------------------------------------------------
# Endpoint: GET /top-predictions
# ---------------------------------------------------------------------------
@router.get(
    "/top-predictions",
    response_model=List[PredictionResponse],
    status_code=status.HTTP_200_OK,
    summary="Return Top N Predictions by Confidence Score",
)
def get_top_predictions(
    limit: int = Query(3, ge=1, le=50, description="Number of top predictions to return"),
):
    """
    Return top N predictions sorted by confidence_score descending.
    """
    try:
        results = prediction_store.get_top_risk_predictions(limit=limit)
        return results
    except Exception as e:
        log.error(f"Error in GET /top-predictions: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve top predictions",
        )


# ---------------------------------------------------------------------------
# Endpoint 3: GET /predictions/{prediction_id}
# ---------------------------------------------------------------------------
@router.get(
    "/predictions/{prediction_id}",
    response_model=PredictionResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve Prediction by ID or Security Event ID",
)
def get_prediction_by_id(prediction_id: str):
    """
    Retrieve a single prediction document by its prediction_id OR event_id (e.g. EVT000034).
    """
    try:
        result = prediction_store.get_prediction_by_id(prediction_id)
        if not result:
            result = prediction_store.get_latest_prediction_by_event_id(prediction_id)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Prediction for ID or Event '{prediction_id}' not found",
            )

        # Enrich prediction with raw security_events document if available
        ev_doc = mongo.get_database()["security_events"].find_one(
            {"event_id": result["event_id"]}, {"_id": 0}
        )
        if ev_doc:
            result["source_event"] = ev_doc

        return result
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error in GET /predictions/{prediction_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve prediction",
        )


# ---------------------------------------------------------------------------
# Endpoint 4: GET /anomalies
# ---------------------------------------------------------------------------
@router.get(
    "/anomalies",
    response_model=List[PredictionResponse],
    status_code=status.HTTP_200_OK,
    summary="Query Anomalous Predictions",
)
def list_anomalies(
    limit: int = Query(
        100, ge=1, le=100, description="Max anomalies to return (1-100)"
    ),
    skip: int = Query(0, ge=0, description="Offset for pagination"),
):
    """
    Return high-risk predictions (final hybrid verdict IN ['Suspicious', 'Critical']), newest first.

    Semantic note:
      - anomaly_label : Isolation Forest raw detection signal
      - verdict       : Final hybrid threat assessment (IF + Rules + RF)
      - /anomalies    : High-risk feed based on final verdict only
    """
    try:
        results = prediction_store.list_anomalies(limit=limit, skip=skip)
        return results
    except Exception as e:
        log.error(f"Error in GET /anomalies: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve anomalies",
        )


# ---------------------------------------------------------------------------
# Endpoint 5: GET /model-performance
# ---------------------------------------------------------------------------
@router.get(
    "/model-performance",
    status_code=status.HTTP_200_OK,
    summary="Return Offline Model Evaluation & Prediction Stats",
)
def get_model_performance():
    """
    Return offline model evaluation metrics and live prediction-distribution stats.

    Note: Metrics represent offline test-set evaluation on the M1 baseline dataset,
    not dynamically calculated real-time accuracy.
    """
    try:
        dist_stats = prediction_store.get_prediction_statistics()

        return {
            "evaluation_type": "Offline Model Evaluation",
            "evaluation_methodology": "80/20 Stratified Train-Test Split on M1 Baseline Dataset",
            "dataset_size": 10000,
            "feature_count": 16,
            "num_classes": 10,
            "isolation_forest": {
                "model_name": "Isolation Forest",
                "model_version": "1.0.0-phase3",
                "n_estimators": 200,
                "contamination": 0.10,
                "random_state": 42,
            },
            "random_forest": {
                "model_name": "Random Forest Classifier",
                "model_version": "1.1.0-phase4.6",
                "n_estimators": 100,
                "max_depth": 15,
                "test_accuracy": 0.0985,
                "test_macro_f1": 0.0961,
                "random_chance_baseline": 0.10,
                "role": "Secondary soft categorical signal (weighted 10% in hybrid scorer)",
            },
            "hybrid_scorer": {
                "version": "1.1.0",
                "weights": {
                    "isolation_forest": 0.50,
                    "security_rules": 0.40,
                    "random_forest": 0.10,
                },
                "verdict_thresholds": {
                    "normal": "[0.0, 34.9]",
                    "suspicious": "[35.0, 64.9]",
                    "critical": "[65.0, 100.0]",
                },
            },
            "known_limitations": [
                "Random Forest performance is near random chance (~9.85% on 10 classes) due to lack of non-leaking signal in synthetic M1 dataset for event_type.",
                "Random Forest is intentionally constrained to 10% score weight as a soft signal.",
                "Metrics reflect offline test-set evaluation, not live real-time accuracy.",
            ],
            "prediction_distribution_stats": dist_stats,
        }
    except Exception as e:
        log.error(f"Error in GET /model-performance: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve model performance",
        )


# ---------------------------------------------------------------------------
# Endpoint 6: GET /threat-summary
# ---------------------------------------------------------------------------
@router.get(
    "/threat-summary",
    response_model=List[ThreatSummaryItem],
    status_code=status.HTTP_200_OK,
    summary="Return Threat-Type Aggregations",
)
def get_threat_summary():
    """
    Return threat-type aggregations (count, average confidence, and percentage per threat type).
    """
    try:
        summary = prediction_store.get_threat_summary()
        # Calculate total predictions for percentage computation
        total = sum(item.get("count", 0) for item in summary)
        for item in summary:
            item["percentage"] = round((item["count"] / total) * 100, 1) if total > 0 else 0.0
        return summary
    except Exception as e:
        log.error(f"Error in GET /threat-summary: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve threat summary",
        )
