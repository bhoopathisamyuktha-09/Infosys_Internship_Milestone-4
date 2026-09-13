"""
ml/anomaly_detection.py — Isolation Forest Anomaly Detection Layer
===================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

This module implements the FIRST detection layer of the M2 two-layer pipeline:

    Preprocessed feature matrix X (16 columns)
            ↓
    Isolation Forest (unsupervised)
            ↓
    Anomaly Label  : "Normal" | "Suspicious"
    Anomaly Score  : float  (lower = more anomalous)

Isolation Forest is trained ONLY on the feature matrix X.
event_type and all leakage fields are strictly excluded — as enforced by
the preprocessing pipeline (ml/preprocessing.py).

Score semantics (sklearn IsolationForest):
    decision_function() returns the mean anomaly score of the input samples.
    The LOWER the score, the MORE anomalous the sample.
    Scores < 0 generally indicate anomalies.
    Scores > 0 generally indicate normal observations.
    The 0-crossing is approximately the decision boundary.

This module does NOT:
  - Contain FastAPI route logic
  - Query MongoDB directly
  - Produce the final 0–100 confidence score (that belongs to scoring_service.py)
  - Train Random Forest
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Artifact path
# ---------------------------------------------------------------------------
_DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "if_model.pkl"

# ---------------------------------------------------------------------------
# Label constants — use strings for explainability in API responses
# ---------------------------------------------------------------------------
LABEL_NORMAL     = "Normal"
LABEL_SUSPICIOUS = "Suspicious"


# ---------------------------------------------------------------------------
# Section 1: Model parameters
# ---------------------------------------------------------------------------

def get_default_params() -> dict[str, Any]:
    """
    Return the default Isolation Forest hyperparameters for this project.

    Parameter rationale:
    ─────────────────────────────────────────────────────────────────────
    n_estimators = 200
        Number of base isolation trees. sklearn default is 100; 200 provides
        more stable score estimates for a 10,000-row dataset with 16 features
        at negligible extra cost. Diminishing returns beyond ~300 for this
        data size.

    max_samples = "auto"
        sklearn draws min(256, n_samples) samples per tree. "auto" is the
        standard recommendation and works well for datasets of this scale.

    contamination = 0.10
        The fraction of observations the model treats as anomalies when
        computing the decision threshold. This is a modeling ASSUMPTION,
        not a factual label from the dataset.
        Rationale for 10%:
          - The M1 dataset contains 10,000 synthetic security events across
            10 event types, including inherently suspicious types such as
            Malware Detection (9.0%), Brute Force (10.6%), SQL Injection
            (11.2%), and Privilege Escalation (11.0%).
          - A 10% contamination estimate is conservative and aligns with the
            approximate fraction of events that domain knowledge would flag
            as genuinely anomalous in a mixed security event log.
          - If ground-truth anomaly labels become available, this parameter
            should be re-tuned accordingly.

    max_features = 1.0
        Use all 16 features at each split. Since the feature set was
        carefully selected (not high-dimensional noise), keeping all features
        is appropriate. Reducing this would be more useful with hundreds of
        features.

    bootstrap = False
        Standard Isolation Forest samples without replacement (the original
        Liu et al. formulation). Keeping this as False matches the paper.

    random_state = 42
        Fixed seed for full reproducibility of tree structure, sample
        selection, and therefore scores. Must remain constant between
        train_models.py and any future retraining.

    n_jobs = -1
        Use all available CPU cores for parallel tree construction.
        Has no effect on scores or predictions, only on training speed.
    """
    return {
        "n_estimators":  200,
        "max_samples":   "auto",
        "contamination": 0.10,
        "max_features":  1.0,
        "bootstrap":     False,
        "random_state":  42,
        "n_jobs":        -1,
    }


# ---------------------------------------------------------------------------
# Section 2: Training
# ---------------------------------------------------------------------------

def train_isolation_forest(
    X: np.ndarray,
    params: dict[str, Any] | None = None,
) -> IsolationForest:
    """
    Train an Isolation Forest on the preprocessed feature matrix X.

    Isolation Forest is fully unsupervised — event_type (y) is never used.
    The model learns which regions of the feature space are sparse (anomalous)
    vs. dense (normal) purely from the feature distribution.

    Args:
        X:      numpy ndarray of shape (n_samples, n_features).
                Must already be preprocessed by SecurityEventPreprocessor.
        params: Optional hyperparameter override dict. If None, uses
                get_default_params().

    Returns:
        Fitted IsolationForest instance.
    """
    if params is None:
        params = get_default_params()

    logger.info(
        f"Training Isolation Forest on {X.shape[0]} samples, "
        f"{X.shape[1]} features. contamination={params.get('contamination')}, "
        f"n_estimators={params.get('n_estimators')}, random_state={params.get('random_state')}"
    )

    model = IsolationForest(**params)
    model.fit(X)

    logger.info("Isolation Forest training complete.")
    return model


# ---------------------------------------------------------------------------
# Section 3: Prediction
# ---------------------------------------------------------------------------

def predict_anomaly(
    model: IsolationForest,
    X: np.ndarray,
) -> dict[str, np.ndarray]:
    """
    Run anomaly detection on a preprocessed feature matrix.

    Returns a dict with three arrays, all aligned with input rows:
      - "raw_prediction":  numpy int array, sklearn output (+1 = normal, -1 = anomaly)
      - "anomaly_label":   numpy str array, human-readable ("Normal" | "Suspicious")
      - "anomaly_score":   numpy float array, decision_function scores

    Score semantics (IMPORTANT — read before using downstream):
      decision_function() returns the AVERAGE path length anomaly score.
      Lower score  → more anomalous (shorter average isolation path)
      Higher score → more normal   (longer average isolation path)
      Threshold ≈ 0:  scores below 0 tend to be flagged as anomalies.

    Args:
        model:  Fitted IsolationForest.
        X:      numpy ndarray of shape (n_samples, n_features).

    Returns:
        Dict with keys "raw_prediction", "anomaly_label", "anomaly_score".
    """
    raw_pred   = model.predict(X)           # +1 or -1
    scores     = model.decision_function(X) # continuous score, lower = more anomalous

    # Map sklearn's +1/-1 to human labels
    labels = np.where(raw_pred == 1, LABEL_NORMAL, LABEL_SUSPICIOUS)

    return {
        "raw_prediction": raw_pred,
        "anomaly_label":  labels,
        "anomaly_score":  scores,
    }


def predict_single(
    model: IsolationForest,
    X_single: np.ndarray,
) -> dict[str, Any]:
    """
    Run anomaly detection on a single-event feature vector of shape (1, n_features).

    Returns a flat dict (scalars, not arrays) suitable for direct use
    in a prediction response payload.

    Args:
        model:    Fitted IsolationForest.
        X_single: numpy ndarray of shape (1, n_features).

    Returns:
        Dict with scalar values:
          "raw_prediction" (int): +1 or -1
          "anomaly_label"  (str): "Normal" or "Suspicious"
          "anomaly_score"  (float): decision_function score
    """
    if X_single.ndim == 1:
        X_single = X_single.reshape(1, -1)

    result = predict_anomaly(model, X_single)
    return {
        "raw_prediction": int(result["raw_prediction"][0]),
        "anomaly_label":  str(result["anomaly_label"][0]),
        "anomaly_score":  float(result["anomaly_score"][0]),
    }


# ---------------------------------------------------------------------------
# Section 4: Artifact persistence
# ---------------------------------------------------------------------------

def save_model(model: IsolationForest, path: str | Path | None = None) -> Path:
    """
    Persist the fitted Isolation Forest to disk using joblib.

    Args:
        model: Fitted IsolationForest instance.
        path:  Optional override path. Defaults to models/if_model.pkl.

    Returns:
        Path where the artifact was saved.
    """
    save_path = Path(path) if path else _DEFAULT_MODEL_PATH
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, save_path)
    logger.info(f"Isolation Forest saved to: {save_path}")
    return save_path


def load_model(path: str | Path | None = None) -> IsolationForest:
    """
    Load a previously trained IsolationForest from disk.

    Called at FastAPI startup via model_loader.py so the model is available
    in memory for every POST /predict call without per-request disk reads.

    Args:
        path: Optional override path. Defaults to models/if_model.pkl.

    Returns:
        Loaded IsolationForest instance.

    Raises:
        FileNotFoundError: if the artifact file does not exist.
        TypeError: if the loaded object is not an IsolationForest.
    """
    load_path = Path(path) if path else _DEFAULT_MODEL_PATH
    if not load_path.exists():
        raise FileNotFoundError(
            f"Isolation Forest artifact not found at: {load_path}. "
            f"Run 'python ml/train_models.py' to generate it."
        )
    model = joblib.load(load_path)
    if not isinstance(model, IsolationForest):
        raise TypeError(
            f"Loaded object at {load_path} is not an IsolationForest instance."
        )
    logger.info(f"Isolation Forest loaded from: {load_path}")
    return model


# ---------------------------------------------------------------------------
# Section 5: Score utilities
# ---------------------------------------------------------------------------

def score_statistics(scores: np.ndarray) -> dict[str, float]:
    """
    Compute basic descriptive statistics for a set of anomaly scores.

    Useful for training reports and model-performance API responses.

    Args:
        scores: 1-D float array of decision_function() outputs.

    Returns:
        Dict with min, max, mean, median, std.
    """
    return {
        "min":    float(np.min(scores)),
        "max":    float(np.max(scores)),
        "mean":   float(np.mean(scores)),
        "median": float(np.median(scores)),
        "std":    float(np.std(scores)),
    }
