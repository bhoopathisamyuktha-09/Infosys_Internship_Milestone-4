"""
services/scoring_service.py — Hybrid Scoring Engine
====================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

This module implements the deterministic hybrid scoring contract defined in:
    BACKEND/docs/scoring_design.md (v1.1.0)

It combines:
  1. Isolation Forest anomaly signal (50% weight)
  2. Security rule engine (40% weight)
  3. Random Forest soft threat-classification signal (10% weight)

It produces:
  - final_confidence score ∈ [0.0, 100.0]
  - verdict ∈ {"Normal", "Suspicious", "Critical"}
  - predicted_threat_type + rf_confidence_note
  - explainable reasons list with exact rule points & severities

Protected Boundaries:
  - Does NOT train models or modify artifacts
  - Does NOT read CSV files or query database directly
  - Does NOT handle FastAPI HTTP requests or routes
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Section 1: Locked Training Reference Constants (IF Normalization)
# ---------------------------------------------------------------------------
# Derived from fitted if_model.pkl applied to full 10,000-event M1 dataset
IF_SCORE_MIN: float = -0.06650378
IF_SCORE_MAX: float = 0.11269725
IF_SCORE_RANGE: float = 0.17920103

# ---------------------------------------------------------------------------
# Section 2: Weight & Verdict Constants
# ---------------------------------------------------------------------------
W_IF: float = 0.50
W_RULE: float = 0.40
W_RF: float = 0.10

VERDICT_NORMAL: str = "Normal"
VERDICT_SUSPICIOUS: str = "Suspicious"
VERDICT_CRITICAL: str = "Critical"

THRESHOLD_SUSPICIOUS: float = 35.0
THRESHOLD_CRITICAL: float = 65.0

RANDOM_BASELINE_PROB: float = 0.10  # 1 / 10 classes


# ---------------------------------------------------------------------------
# Section 3: Anomaly Normalization
# ---------------------------------------------------------------------------
def normalize_anomaly_score(raw_score: float) -> float:
    """
    Transform raw IsolationForest.decision_function score to 0–100 scale.

    Formula:
        anomaly_normalized = clip((IF_SCORE_MAX - raw_score) / IF_SCORE_RANGE * 100, 0, 100)

    Semantics:
        Lower raw_score (more anomalous) -> Higher normalized score (up to 100.0)
        Higher raw_score (more normal)    -> Lower normalized score (down to 0.0)
    """
    val = (IF_SCORE_MAX - float(raw_score)) / IF_SCORE_RANGE * 100.0
    return float(np.clip(val, 0.0, 100.0))


# ---------------------------------------------------------------------------
# Section 4: Random Forest Soft Signal Normalization
# ---------------------------------------------------------------------------
def compute_rf_signal(top_prob: float) -> Tuple[float, str]:
    """
    Normalize RF top class probability relative to 10-class random baseline (0.10).

    Formula:
        rf_score = clip((top_prob - 0.10) / 0.90 * 100, 0, 100)

    Thresholds for rf_confidence_note:
        top_prob < 0.15              -> "low"
        0.15 <= top_prob < 0.50       -> "moderate"
        top_prob >= 0.50              -> "high"

    Returns:
        (rf_score [0..100], rf_confidence_note)
    """
    prob = float(top_prob)
    rf_score = float(np.clip((prob - RANDOM_BASELINE_PROB) / (1.0 - RANDOM_BASELINE_PROB) * 100.0, 0.0, 100.0))

    if prob < 0.15:
        confidence_note = "low"
    elif prob < 0.50:
        confidence_note = "moderate"
    else:
        confidence_note = "high"

    return rf_score, confidence_note


# ---------------------------------------------------------------------------
# Section 5: Security Rule Engine
# ---------------------------------------------------------------------------
def evaluate_security_rules(
    event: Dict[str, Any],
    anomaly_label: str,
    anomaly_normalized: float,
) -> Tuple[float, List[str], List[Dict[str, Any]]]:
    """
    Evaluate the 9 scored security rules and IF anomaly explanation signal.

    Inputs from event (with safe defaults if missing):
        malware_flag: int (0/1)
        failed_login_attempts: int
        severity_score: int (0..4)
        cvss_score: float (0.0..10.0)
        impossible_travel_flag: int (0/1)
        after_hours_flag: int (0/1)
        hour: int

    Mutually Exclusive Groups:
        Failed Logins: RULE_FAILED_LOGINS_HIGH (40pt) vs RULE_FAILED_LOGINS_MED (20pt)
        Severity:      RULE_CRITICAL_SEVERITY (35pt) vs RULE_HIGH_SEVERITY (20pt)
        CVSS:          RULE_HIGH_CVSS (30pt) vs RULE_MEDIUM_CVSS (15pt)

    Returns:
        (rule_score [0..100], triggered_rules, reasons)
    """
    # Extract values with safe defaults
    malware_flag = int(event.get("malware_flag", 0) or 0)
    failed_logins = int(event.get("failed_login_attempts", 0) or 0)
    severity_score = int(event.get("severity_score", 0) or 0)
    cvss_score = float(event.get("cvss_score", 0.0) or 0.0)
    impossible_travel = int(event.get("impossible_travel_flag", 0) or 0)
    after_hours = int(event.get("after_hours_flag", 0) or 0)
    hour = int(event.get("hour", 12) if event.get("hour") is not None else 12)

    triggered_scored: List[Dict[str, Any]] = []

    # Rule 1: Malware
    if malware_flag == 1:
        triggered_scored.append({
            "rule_id": "RULE_MALWARE",
            "reason": "Malware activity detected on this event",
            "points": 50,
            "severity": "Critical",
        })

    # Rule 2: Impossible Travel
    if impossible_travel == 1:
        triggered_scored.append({
            "rule_id": "RULE_IMPOSSIBLE_TRAVEL",
            "reason": "Impossible travel detected: country changed within 24h window",
            "points": 45,
            "severity": "Critical",
        })

    # Rule 3: Failed Logins (Mutually Exclusive)
    if failed_logins >= 15:
        triggered_scored.append({
            "rule_id": "RULE_FAILED_LOGINS_HIGH",
            "reason": f"Excessive failed login attempts ({failed_logins})",
            "points": 40,
            "severity": "High",
        })
    elif 8 <= failed_logins < 15:
        triggered_scored.append({
            "rule_id": "RULE_FAILED_LOGINS_MED",
            "reason": f"Elevated failed login attempts ({failed_logins})",
            "points": 20,
            "severity": "Medium",
        })

    # Rule 4: Severity Score (Mutually Exclusive)
    if severity_score >= 4:
        triggered_scored.append({
            "rule_id": "RULE_CRITICAL_SEVERITY",
            "reason": "Event carries Critical severity rating",
            "points": 35,
            "severity": "Critical",
        })
    elif severity_score == 3:
        triggered_scored.append({
            "rule_id": "RULE_HIGH_SEVERITY",
            "reason": "Event carries High severity rating",
            "points": 20,
            "severity": "High",
        })

    # Rule 5: CVSS Score (Mutually Exclusive)
    if cvss_score >= 9.0:
        triggered_scored.append({
            "rule_id": "RULE_HIGH_CVSS",
            "reason": f"Critical CVSS vulnerability score ({cvss_score})",
            "points": 30,
            "severity": "Critical",
        })
    elif 7.0 <= cvss_score < 9.0:
        triggered_scored.append({
            "rule_id": "RULE_MEDIUM_CVSS",
            "reason": f"High CVSS vulnerability score ({cvss_score})",
            "points": 15,
            "severity": "High",
        })

    # Rule 6: After Hours
    if after_hours == 1:
        triggered_scored.append({
            "rule_id": "RULE_AFTER_HOURS",
            "reason": f"Activity occurred outside business hours (hour={hour})",
            "points": 10,
            "severity": "Low",
        })

    # Calculate rule_score (sum of scored rules capped at 100)
    raw_rule_points = sum(r["points"] for r in triggered_scored)
    rule_score = float(min(raw_rule_points, 100))

    # Sort scored rules by points descending
    triggered_scored.sort(key=lambda x: x["points"], reverse=True)

    triggered_rule_ids = [r["rule_id"] for r in triggered_scored]

    # Assemble reasons list
    reasons: List[Dict[str, Any]] = list(triggered_scored)

    # Explanation-only IF Anomaly signal (points = 0, NOT added to rule_score)
    if anomaly_label == "Suspicious":
        reasons.append({
            "rule_id": "IF_ANOMALY_SIGNAL",
            "reason": f"Isolation Forest flagged this event as anomalous (normalized score: {round(anomaly_normalized, 1)})",
            "points": 0,
            "severity": "Medium",
        })

    return rule_score, triggered_rule_ids, reasons


# ---------------------------------------------------------------------------
# Section 6: Main Hybrid Scorer
# ---------------------------------------------------------------------------
def calculate_hybrid_score(
    event: Dict[str, Any],
    if_raw_score: float,
    if_anomaly_label: str,
    rf_predicted_type: str,
    rf_top_prob: float,
) -> Dict[str, Any]:
    """
    Calculate final hybrid threat score, verdict, and explainable reasons.

    Args:
        event: Enriched event dictionary (raw fields + derived features)
        if_raw_score: Raw IsolationForest.decision_function output
        if_anomaly_label: "Normal" or "Suspicious"
        rf_predicted_type: Predicted threat type class label string
        rf_top_prob: Top class probability from RandomForest.predict_proba

    Returns:
        Structured prediction result dictionary conforming to scoring_design.md §8.1
    """
    # 1. Isolation Forest signal
    anomaly_norm = normalize_anomaly_score(if_raw_score)

    # 2. Random Forest signal
    rf_score, rf_confidence_note = compute_rf_signal(rf_top_prob)

    # 3. Security Rule Engine
    rule_score, triggered_rules, reasons = evaluate_security_rules(
        event, if_anomaly_label, anomaly_norm
    )

    # 4. Score combination
    raw_confidence = (W_IF * anomaly_norm) + (W_RULE * rule_score) + (W_RF * rf_score)
    confidence_score = round(float(np.clip(raw_confidence, 0.0, 100.0)), 1)

    # 5. Hard Overrides
    malware_flag = int(event.get("malware_flag", 0) or 0)
    impossible_travel = int(event.get("impossible_travel_flag", 0) or 0)

    if malware_flag == 1:
        confidence_score = max(confidence_score, THRESHOLD_CRITICAL)
    if impossible_travel == 1:
        confidence_score = max(confidence_score, THRESHOLD_SUSPICIOUS)

    # 6. Verdict determination
    if confidence_score >= THRESHOLD_CRITICAL:
        verdict = VERDICT_CRITICAL
    elif confidence_score >= THRESHOLD_SUSPICIOUS:
        verdict = VERDICT_SUSPICIOUS
    else:
        verdict = VERDICT_NORMAL

    # 7. Final output assembly
    event_id = str(event.get("event_id", ""))

    return {
        "event_id": event_id,
        "verdict": verdict,
        "confidence_score": confidence_score,
        "predicted_threat_type": str(rf_predicted_type),
        "rf_top_probability": float(rf_top_prob),
        "rf_confidence_note": rf_confidence_note,
        "anomaly_label": str(if_anomaly_label),
        "anomaly_score": round(anomaly_norm, 1),
        "anomaly_score_raw": float(if_raw_score),
        "anomaly_normalized": round(anomaly_norm, 1),
        "rule_score": round(rule_score, 1),
        "triggered_rules": triggered_rules,
        "reasons": reasons,
        "model_signals": {
            "if_anomaly_normalized": round(anomaly_norm, 1),
            "rf_score_normalized": round(rf_score, 1),
            "rule_score": round(rule_score, 1),
        },
    }
