"""
ml/model_loader.py — Centralized Production Model Loader Singleton
===================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

Provides a clean, centralized interface for loading and caching
persisted production ML artifacts into memory:
  - models/preprocessor.pkl (Preprocessor transformer)
  - models/if_model.pkl    (Isolation Forest anomaly detector)
  - models/clf_model.pkl   (Random Forest threat classifier)

Key Guarantees:
  - Caches artifacts in memory as thread-safe singletons
  - NEVER refits or retrains models during live inference
  - NEVER modifies persisted .pkl artifacts
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Tuple

from ml.anomaly_detection import load_model as load_if_model
from ml.classifier import load_model as load_rf_model
from ml.preprocessing import load_preprocessor

logger = logging.getLogger("model_loader")

_preprocessor = None
_isolation_forest = None
_classifier = None


def get_preprocessor(model_path: Any = None, force_reload: bool = False) -> Any:
    """Get cached singleton Preprocessor instance."""
    global _preprocessor
    if force_reload or _preprocessor is None:
        _preprocessor = load_preprocessor(model_path)
    return _preprocessor


def get_isolation_forest(model_path: Any = None, force_reload: bool = False) -> Any:
    """Get cached singleton Isolation Forest instance."""
    global _isolation_forest
    if force_reload or _isolation_forest is None:
        _isolation_forest = load_if_model(model_path)
    return _isolation_forest


def get_classifier(model_path: Any = None, force_reload: bool = False) -> Any:
    """Get cached singleton Random Forest classifier instance."""
    global _classifier
    if force_reload or _classifier is None:
        _classifier = load_rf_model(model_path)
    return _classifier


def get_loaded_models(
    preprocessor_path: Any = None,
    if_model_path: Any = None,
    clf_model_path: Any = None,
    force_reload: bool = False,
) -> Tuple[Any, Any, Any]:
    """
    Retrieve all three production ML singletons in one call.

    Returns:
        Tuple (preprocessor, isolation_forest, classifier)
    """
    prep = get_preprocessor(preprocessor_path, force_reload=force_reload)
    if_mod = get_isolation_forest(if_model_path, force_reload=force_reload)
    clf_mod = get_classifier(clf_model_path, force_reload=force_reload)
    return prep, if_mod, clf_mod
