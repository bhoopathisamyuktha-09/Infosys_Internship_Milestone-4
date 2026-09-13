"""
ml/classifier.py — Random Forest Threat Classification Layer
=============================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

This module implements the SECOND detection layer of the M2 two-layer pipeline:

    Preprocessed feature matrix X (16 columns)
            ↓
    Random Forest Classifier (supervised)
            ↓
    Predicted Threat Type   (e.g. "Brute Force", "SQL Injection Attempt")
    Class Probabilities     (one probability per event_type class)

Target label y = event_type   (10 balanced classes from M1 dataset)

IMPORTANT LIMITATION (documented):
    The Random Forest is trained to classify the M1 dataset's event_type
    categories. It learns to distinguish patterns that co-occur with these
    labels in the training data. This is the supervised threat-classification
    layer of the M2 demonstration system. It does NOT constitute proof that
    the model can identify previously unseen real-world attack variants
    beyond the scope of the training distribution.

This module does NOT:
  - Contain FastAPI route logic
  - Query MongoDB directly
  - Produce the final 0–100 confidence score (belongs to scoring_service.py)
  - Train or reference the Isolation Forest
  - Accept event_type or any leakage field as a model input feature
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Artifact path
# ---------------------------------------------------------------------------
_DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "clf_model.pkl"


# ---------------------------------------------------------------------------
# Section 1: Model parameters
# ---------------------------------------------------------------------------

def get_default_params() -> dict[str, Any]:
    """
    Return the default Random Forest hyperparameters for this project.

    Parameter rationale:
    ─────────────────────────────────────────────────────────────────────
    n_estimators = 100
        Phase 4.5 diagnostic confirmed the M1 dataset has no meaningful
        non-leaking signal for event_type (MI ≈ 0 for all contract features;
        baseline accuracy ~= random chance at 10%). The RF is used as a
        secondary soft-signal layer in scoring_service.py, not a standalone
        detector. 100 trees provides stable probability estimates for this role
        while reducing the artifact from ~359 MB to ~20-40 MB.
        The previous 300-tree model produced identical accuracy, confirming the
        extra 200 trees memorised noise rather than learning signal.

    max_depth = 15
        With max_depth=None and 8,000 training rows, trees grew to depth ~14-16
        (up to ~16,000 nodes each), producing a 359 MB artifact that performed
        at chance level. Capping at 15 is sufficient to represent any genuine
        pattern in a 16-feature space while dramatically reducing artifact size.
        Empirically, RF accuracy on this dataset is insensitive to max_depth
        because the signal is absent, not because the trees are too shallow.

    min_samples_split = 2
        sklearn default. Appropriate for a clean, balanced dataset.

    min_samples_leaf = 1
        sklearn default. No leaf pruning needed.

    max_features = "sqrt"
        sqrt(16) ≈ 4 candidate features per split — Breiman 2001 optimum
        for classification. Ensures tree diversity.

    class_weight = None
        Classes are nearly perfectly balanced (imbalance ratio 1.28×).
        No reweighting needed.

    bootstrap = True
        Standard bagging with replacement.

    random_state = 42
        Fixed seed for full reproducibility.

    n_jobs = -1
        All CPU cores for parallel tree construction.
    """
    return {
        "n_estimators":      100,
        "max_depth":         15,
        "min_samples_split": 2,
        "min_samples_leaf":  1,
        "max_features":      "sqrt",
        "class_weight":      None,
        "bootstrap":         True,
        "random_state":      42,
        "n_jobs":            -1,
    }


# ---------------------------------------------------------------------------
# Section 2: Training
# ---------------------------------------------------------------------------

def train_random_forest(
    X_train: np.ndarray,
    y_train: np.ndarray,
    params: dict[str, Any] | None = None,
) -> RandomForestClassifier:
    """
    Train a Random Forest classifier on the preprocessed feature matrix.

    X_train must NOT contain event_type, technique_id, technique_name,
    tactic, risk_level, login_risk, or threat_confidence — these are
    excluded by the preprocessing pipeline and enforced in prepare_training_data().

    Args:
        X_train: numpy ndarray of shape (n_samples, n_features).
                 Must already be preprocessed by SecurityEventPreprocessor.
        y_train: 1-D array of event_type labels (strings or encoded).
        params:  Optional hyperparameter override dict. If None, uses
                 get_default_params().

    Returns:
        Fitted RandomForestClassifier instance.
    """
    if params is None:
        params = get_default_params()

    logger.info(
        f"Training Random Forest on {X_train.shape[0]} samples, "
        f"{X_train.shape[1]} features, {len(np.unique(y_train))} classes. "
        f"n_estimators={params.get('n_estimators')}, "
        f"random_state={params.get('random_state')}"
    )

    model = RandomForestClassifier(**params)
    model.fit(X_train, y_train)

    logger.info("Random Forest training complete.")
    return model


# ---------------------------------------------------------------------------
# Section 3: Prediction
# ---------------------------------------------------------------------------

def predict_threat(
    model: RandomForestClassifier,
    X: np.ndarray,
) -> dict[str, Any]:
    """
    Run threat classification on a preprocessed feature matrix.

    Returns a dict with three entries, all row-aligned with X:
      - "predicted_class":   numpy str array of predicted event_type labels
      - "probabilities":     numpy float array of shape (n_samples, n_classes)
      - "class_names":       list of class label strings (ordering matches
                             probability columns)

    Args:
        model: Fitted RandomForestClassifier.
        X:     numpy ndarray of shape (n_samples, n_features).

    Returns:
        Dict with keys "predicted_class", "probabilities", "class_names".
    """
    predicted_class = model.predict(X)
    probabilities   = model.predict_proba(X)  # shape: (n_samples, n_classes)
    class_names     = list(model.classes_)

    return {
        "predicted_class": predicted_class,
        "probabilities":   probabilities,
        "class_names":     class_names,
    }


def predict_single(
    model: RandomForestClassifier,
    X_single: np.ndarray,
) -> dict[str, Any]:
    """
    Run threat classification on a single-event feature vector.

    Returns a flat dict (scalars / lists) suitable for direct use
    in a prediction response payload.

    Args:
        model:    Fitted RandomForestClassifier.
        X_single: numpy ndarray of shape (1, n_features).

    Returns:
        Dict with:
          "predicted_class"   (str):         e.g. "Brute Force"
          "top_probability"   (float):       probability of predicted class
          "class_probabilities" (dict):      {class_name: probability}
    """
    if X_single.ndim == 1:
        X_single = X_single.reshape(1, -1)

    result      = predict_threat(model, X_single)
    class_names = result["class_names"]
    probs_row   = result["probabilities"][0]

    class_prob_dict = {
        cls: float(prob)
        for cls, prob in zip(class_names, probs_row)
    }
    predicted   = str(result["predicted_class"][0])
    top_prob    = float(class_prob_dict[predicted])

    return {
        "predicted_class":     predicted,
        "top_probability":     top_prob,
        "class_probabilities": class_prob_dict,
    }


# ---------------------------------------------------------------------------
# Section 4: Artifact persistence
# ---------------------------------------------------------------------------

def save_model(model: RandomForestClassifier, path: str | Path | None = None) -> Path:
    """
    Persist the fitted Random Forest to disk using joblib.

    Args:
        model: Fitted RandomForestClassifier instance.
        path:  Optional override path. Defaults to models/clf_model.pkl.

    Returns:
        Path where the artifact was saved.
    """
    save_path = Path(path) if path else _DEFAULT_MODEL_PATH
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, save_path)
    logger.info(f"Random Forest saved to: {save_path}")
    return save_path


def load_model(path: str | Path | None = None) -> RandomForestClassifier:
    """
    Load a previously trained RandomForestClassifier from disk.

    Called at FastAPI startup via model_loader.py so the model is available
    in memory for every POST /predict call without per-request disk reads.

    Args:
        path: Optional override path. Defaults to models/clf_model.pkl.

    Returns:
        Loaded RandomForestClassifier instance.

    Raises:
        FileNotFoundError: if the artifact file does not exist.
        TypeError: if the loaded object is not a RandomForestClassifier.
    """
    load_path = Path(path) if path else _DEFAULT_MODEL_PATH
    if not load_path.exists():
        raise FileNotFoundError(
            f"Random Forest artifact not found at: {load_path}. "
            f"Run 'python ml/train_models.py' to generate it."
        )
    model = joblib.load(load_path)
    if not isinstance(model, RandomForestClassifier):
        raise TypeError(
            f"Loaded object at {load_path} is not a RandomForestClassifier instance."
        )
    logger.info(f"Random Forest loaded from: {load_path}")
    return model


# ---------------------------------------------------------------------------
# Section 5: Feature importance utility
# ---------------------------------------------------------------------------

def feature_importances_report(
    model: RandomForestClassifier,
    feature_names: list[str],
    top_n: int = 16,
) -> list[dict[str, Any]]:
    """
    Extract and rank feature importances from the fitted Random Forest.

    Mapped back to the actual ENCODED feature names (16 columns, not 12
    logical features) because that is what the model actually operates on.

    Args:
        model:         Fitted RandomForestClassifier.
        feature_names: Ordered list of encoded feature column names from
                       SecurityEventPreprocessor.feature_names.
        top_n:         Number of top features to return (default: all 16).

    Returns:
        List of dicts sorted by importance descending:
          [{"feature": str, "importance": float, "rank": int}, ...]
    """
    importances = model.feature_importances_
    ranked = sorted(
        zip(feature_names, importances),
        key=lambda x: x[1],
        reverse=True,
    )
    return [
        {"rank": i + 1, "feature": name, "importance": float(imp)}
        for i, (name, imp) in enumerate(ranked[:top_n])
    ]
