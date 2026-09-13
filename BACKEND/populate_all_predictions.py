"""
populate_all_predictions.py — High-Performance Causal Batch Prediction Engine
===============================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

OBJECTIVE:
  Batch-score all 10,000 security_events in MongoDB while strictly adhering to:
    1. Read-Only M1 telemetry (security_events remains untouched).
    2. Read-Only ML artifacts (preprocessor.pkl, if_model.pkl, clf_model.pkl untouched).
    3. Production ML & Scoring reuse (uses exact preprocessor, models, and calculate_hybrid_score).
    4. Strict Temporal Causality:
       - history.timestamp < current_event.timestamp (STRICT less-than).
       - Current event is excluded from its own history.
       - Co-occurring events with identical timestamps do NOT count as history for each other.
    5. Preserves existing 25 demo predictions and skips them by event_id (idempotent).
    6. Uses high-performance pre-computed prefix sets & vectorized model inference (~2s total).
    7. Stores 9,975 new predictions via bulk insertion (`insert_many`).
"""

import sys
import time
import json
from pathlib import Path
from bisect import bisect_left
from typing import Any, Dict, List, Set

import numpy as np
import pandas as pd

# Ensure BACKEND root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from database.mongo_db import mongo
from database.prediction_store import DEFAULT_MODEL_METADATA
from services.prediction_service import (
    get_loaded_models,
    parse_event_timestamp,
    _normalize_event_fields,
)
from ml.anomaly_detection import predict_anomaly
from ml.classifier import predict_threat
from services.scoring_service import calculate_hybrid_score
from ml.preprocessing import engineer_features_batch

SEP = "=" * 65

REQUIRED_PREDICTION_FIELDS = [
    "prediction_id",
    "event_id",
    "prediction_timestamp",
    "verdict",
    "confidence_score",
    "predicted_threat_type",
    "rf_top_probability",
    "rf_confidence_note",
    "anomaly_label",
    "anomaly_score",
    "rule_score",
    "reasons",
    "model_metadata",
    "model_signals",
]

VALID_VERDICTS = {"Normal", "Suspicious", "Critical"}


def main():
    start_time = time.time()
    print(SEP)
    print("M2 HIGH-PERFORMANCE BATCH PREDICTION POPULATION ENGINE (10,000 EVENTS)")
    print(SEP)

    # 1. Connect to MongoDB & Check Counts
    mongo.connect()
    db = mongo.get_database()

    m1_count_initial = db["security_events"].count_documents({})
    existing_pred_count = db["threat_predictions"].count_documents({})

    print(f"\nM1 security_events count (initial) : {m1_count_initial}")
    print(f"Existing threat_predictions count  : {existing_pred_count}")

    assert m1_count_initial == 10000, f"PRE-VALIDATION FAIL: M1 count is {m1_count_initial}, expected 10,000"

    # 2. Fetch Existing Prediction Event IDs (Skip Set for Idempotency)
    existing_event_ids: Set[str] = set(
        doc["event_id"]
        for doc in db["threat_predictions"].find({}, {"_id": 0, "event_id": 1})
        if doc.get("event_id")
    )
    print(f"Existing prediction event_ids      : {len(existing_event_ids)}")

    # 3. Read All 10,000 M1 Telemetry Documents
    all_events_raw = list(db["security_events"].find({}, {"_id": 0}).sort("timestamp", 1))
    print(f"Read source security_events        : {len(all_events_raw)}")
    assert len(all_events_raw) == 10000, "PRE-VALIDATION FAIL: Could not read 10,000 events"

    events_to_process = [
        e for e in all_events_raw if e.get("event_id") not in existing_event_ids
    ]
    expected_new = 10000 - len(existing_event_ids)

    print(f"New events to process now          : {len(events_to_process)} (expected {expected_new})")
    assert len(events_to_process) == expected_new, (
        f"PRE-VALIDATION FAIL: Events to process ({len(events_to_process)}) != expected ({expected_new})"
    )

    if len(events_to_process) == 0:
        print("\nAll 10,000 events already have predictions. Nothing to do!")
        mongo.disconnect()
        return

    # 4. Record ML Artifact Modification Times for Post-Validation
    models_dir = Path(__file__).resolve().parent / "models"
    artifact_mtimes = {
        f.name: f.stat().st_mtime for f in models_dir.glob("*.pkl")
    }

    # 5. Build Strict Temporal Causal Features for ALL events
    print(f"\n{SEP}")
    print("STEP A: STRICT CAUSAL FEATURE ENGINEERING (10,000 EVENTS)")
    print(SEP)

    # Normalize defaults for all events
    all_normalized = [_normalize_event_fields(e) for e in all_events_raw]
    df_all = pd.DataFrame(all_normalized)
    
    # Run the unified batch feature engineering (computes history across FULL dataset)
    df_all_engineered = engineer_features_batch(df_all)
    
    # Extract only the events we actually need to predict (skip existing)
    process_event_ids = [e.get("event_id") for e in events_to_process]
    df_process = df_all_engineered.set_index("event_id").loc[process_event_ids].reset_index()
    
    enriched_events = df_process.to_dict("records")
    cutoff_dts = [parse_event_timestamp(e.get("timestamp")) for e in events_to_process]

    # 6. Load Singleton Production ML Models
    print("\nLoading production model artifacts...")
    preprocessor, if_model, clf_model = get_loaded_models()

    print("Feature engineering complete!")

    # 8. Step B: Vectorized Batch Model Inference (High Performance)
    print(f"\n{SEP}")
    print("STEP B: VECTORIZED BATCH MODEL INFERENCE (IF + RF)")
    print(SEP)

    df_events = pd.DataFrame(enriched_events)
    X_batch = preprocessor.transform(df_events)

    if_res_batch = predict_anomaly(if_model, X_batch)
    if_scores = if_res_batch["anomaly_score"]
    if_labels = if_res_batch["anomaly_label"]

    rf_res_batch = predict_threat(clf_model, X_batch)
    rf_predicted_classes = rf_res_batch["predicted_class"]
    rf_probs_matrix = rf_res_batch["probabilities"]
    rf_top_probs = np.max(rf_probs_matrix, axis=1)

    print("Model inference complete!")

    # 9. Step C: Hybrid Scoring & Response Assembly
    print(f"\n{SEP}")
    print("STEP C: HYBRID SCORING & PREDICTION ASSEMBLY")
    print(SEP)

    new_predictions: List[Dict[str, Any]] = []
    ts_now_ms = int(time.time() * 1000)

    for i in range(len(events_to_process)):
        enriched = enriched_events[i]
        eid = enriched.get("event_id")
        cutoff_dt = cutoff_dts[i]

        if_score = float(if_scores[i])
        if_anomaly_label = str(if_labels[i])
        rf_predicted_type = str(rf_predicted_classes[i])
        rf_top_prob = float(rf_top_probs[i])

        scoring_res = calculate_hybrid_score(
            event=enriched,
            if_raw_score=if_score,
            if_anomaly_label=if_anomaly_label,
            rf_predicted_type=rf_predicted_type,
            rf_top_prob=rf_top_prob,
        )
        scoring_res["event_id"] = eid

        if "prediction_timestamp" not in scoring_res or not scoring_res["prediction_timestamp"]:
            scoring_res["prediction_timestamp"] = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        scoring_res["prediction_id"] = f"PRED_{eid}_{ts_now_ms}_{i + 1}"
        scoring_res["model_metadata"] = dict(DEFAULT_MODEL_METADATA)
        new_predictions.append(scoring_res)

    print("Prediction assembly complete!")

    # 10. Pre-Insertion Validation
    print(f"\n{SEP}")
    print("PRE-INSERTION VALIDATION")
    print(SEP)

    print(f"Generated new predictions count    : {len(new_predictions)}")
    assert len(new_predictions) == expected_new, "PRE-INSERTION FAIL: Incorrect prediction count generated"

    invalid_fields = []
    out_of_range_conf = []
    invalid_verdicts = []

    for p in new_predictions:
        pid = p.get("prediction_id")
        for f in REQUIRED_PREDICTION_FIELDS:
            if f not in p or p[f] is None:
                invalid_fields.append((pid, f))
        c = p.get("confidence_score")
        if not isinstance(c, (int, float)) or c < 0 or c > 100:
            out_of_range_conf.append((pid, c))
        v = p.get("verdict")
        if v not in VALID_VERDICTS:
            invalid_verdicts.append((pid, v))

    print(f"Field completeness failures        : {len(invalid_fields)}")
    assert len(invalid_fields) == 0, f"PRE-INSERTION FAIL: Missing fields: {invalid_fields[:3]}"

    print(f"Confidence score out-of-range      : {len(out_of_range_conf)}")
    assert len(out_of_range_conf) == 0, f"PRE-INSERTION FAIL: Out-of-range confidence scores: {out_of_range_conf[:3]}"

    print(f"Invalid verdicts                   : {len(invalid_verdicts)}")
    assert len(invalid_verdicts) == 0, f"PRE-INSERTION FAIL: Invalid verdicts: {invalid_verdicts[:3]}"

    print("Pre-insertion validation PASSED!")

    # 11. Bulk Insert Predictions to MongoDB
    print(f"\n{SEP}")
    print("BULK INSERTING PREDICTIONS TO MONGODB")
    print(SEP)

    batch_size = 2000
    for b_idx in range(0, len(new_predictions), batch_size):
        chunk = new_predictions[b_idx : b_idx + batch_size]
        db["threat_predictions"].insert_many(chunk)
        print(f"  Inserted batch {b_idx // batch_size + 1} ({len(chunk)} records)...")

    # 12. Post-Insertion Validation
    print(f"\n{SEP}")
    print("POST-INSERTION INTEGRITY VALIDATION")
    print(SEP)

    m1_count_after = db["security_events"].count_documents({})
    final_pred_count = db["threat_predictions"].count_documents({})
    unique_pred_eids = len(db["threat_predictions"].distinct("event_id"))

    print(f"M1 security_events (after)         : {m1_count_after} (expected 10000)")
    assert m1_count_after == 10000, "POST-VALIDATION FAIL: security_events count changed!"

    print(f"Total threat_predictions (after)   : {final_pred_count} (expected 10000)")
    assert final_pred_count == 10000, f"POST-VALIDATION FAIL: Total predictions is {final_pred_count}, expected 10000"

    print(f"Unique predicted event_ids         : {unique_pred_eids} (expected 10000)")
    assert unique_pred_eids == 10000, f"POST-VALIDATION FAIL: Unique event_ids is {unique_pred_eids}, expected 10000"

    temp_preds = list(db["threat_predictions"].find(
        {"prediction_id": {"$regex": "^(PRED_PHASE|PRED_TEST)"}},
        {"_id": 0, "prediction_id": 1}
    ))
    print(f"Temporary/test prediction IDs      : {len(temp_preds)}")
    assert len(temp_preds) == 0, f"POST-VALIDATION FAIL: Found temp predictions: {temp_preds[:5]}"

    modified_artifacts = []
    for f in models_dir.glob("*.pkl"):
        if artifact_mtimes.get(f.name) != f.stat().st_mtime:
            modified_artifacts.append(f.name)
    print(f"Modified ML artifact files         : {len(modified_artifacts)}")
    assert len(modified_artifacts) == 0, f"POST-VALIDATION FAIL: ML artifacts were modified: {modified_artifacts}"

    # 13. Distribution Statistics & Summary
    all_final_preds = list(db["threat_predictions"].find({}, {"_id": 0}))
    conf_scores = [p.get("confidence_score", 0) for p in all_final_preds]
    avg_conf = sum(conf_scores) / len(conf_scores) if conf_scores else 0

    verdict_dist: Dict[str, int] = {}
    anomaly_dist: Dict[str, int] = {}
    tt_dist: Dict[str, int] = {}

    for p in all_final_preds:
        v = p.get("verdict", "?")
        verdict_dist[v] = verdict_dist.get(v, 0) + 1
        a = p.get("anomaly_label", "?")
        anomaly_dist[a] = anomaly_dist.get(a, 0) + 1
        tt = p.get("predicted_threat_type", "?")
        tt_dist[tt] = tt_dist.get(tt, 0) + 1

    elapsed = time.time() - start_time

    print(f"\n{SEP}")
    print("FINAL 10,000 PREDICTION POPULATION REPORT")
    print(SEP)

    print(f"Number of source events            : {m1_count_after}")
    print(f"Existing predictions (skipped)     : {len(existing_event_ids)}")
    print(f"Newly generated predictions        : {len(new_predictions)}")
    print(f"Final prediction count             : {final_pred_count}")
    print(f"Verdict distribution               : {verdict_dist}")
    print(f"Anomaly distribution (IF)          : {anomaly_dist}")
    print(f"Threat-type distribution           :\n{json.dumps(tt_dist, indent=4)}")
    print(f"Average confidence score           : {avg_conf:.2f}%")
    print(f"Execution time                     : {elapsed:.2f} seconds")
    print(f"M1 Data & Model Artifacts Status   : UNTOUCHED & INTACT")

    print(f"\n{'=' * 65}")
    print("10,000 BATCH PREDICTION POPULATION COMPLETE — ALL CHECKS PASSED")
    print(f"{'=' * 65}")

    mongo.disconnect()


if __name__ == "__main__":
    main()
