"""
ml/train_models.py — Offline Model Training Script
====================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

This script trains and saves all M2 ML model artifacts.

Artifacts produced:
  models/preprocessor.pkl  — fitted feature preprocessing pipeline
  models/if_model.pkl      — trained Isolation Forest (Phase 3)
  models/clf_model.pkl     — trained Random Forest classifier (Phase 4)

Usage:
    python ml/train_models.py

Run from BACKEND/ directory.
FastAPI MUST NOT call this script at startup — models are loaded from
pre-trained .pkl artifacts via ml/model_loader.py.

Protected files (never modified):
    BACKEND/data/*.csv  |  all M1 routes, services, database modules
"""

from __future__ import annotations

import sys
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)

# Ensure BACKEND/ is on the path when run directly
_BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BACKEND_DIR))

from ml.preprocessing import (
    prepare_training_data,
    SecurityEventPreprocessor,
    load_preprocessor,
    load_training_dataframe,
    engineer_features_batch,
    LOGICAL_FEATURES,
)
from ml.anomaly_detection import (
    train_isolation_forest     as _train_if,
    predict_anomaly,
    save_model                 as _save_if,
    load_model                 as _load_if,
    score_statistics,
    get_default_params         as _if_params,
    LABEL_NORMAL,
    LABEL_SUSPICIOUS,
)
from ml.classifier import (
    train_random_forest        as _train_rf,
    predict_threat,
    save_model                 as _save_rf,
    load_model                 as _load_rf,
    get_default_params         as _rf_params,
    feature_importances_report,
)

# ---------------------------------------------------------------------------
# Logging / formatting helpers
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("train_models")

SEP  = "=" * 65
SEP2 = "-" * 65

# Fixed random state used consistently throughout (split + RF)
RANDOM_STATE = 42


def _header(title: str) -> None:
    print(f"\n{SEP}\n{title}\n{SEP}")


# ===========================================================================
# STEP 1 — Data loading & preprocessing
# ===========================================================================

def step_prepare_data() -> tuple[np.ndarray, pd.Series, SecurityEventPreprocessor, pd.DataFrame]:
    """
    Load M1 CSV, engineer features, fit preprocessor, build full X matrix.
    Preprocessor is reloaded from disk if it already exists; otherwise fitted
    fresh on the full dataset and saved.

    Returns: (X_full, y_full, preprocessor, df_raw)
    """
    _header("STEP 1 — DATA LOADING & PREPROCESSING")

    df_raw = load_training_dataframe()
    log.info(f"Loaded {df_raw.shape[0]} rows, {df_raw.shape[1]} columns from security_events.csv")

    preprocessor_path = _BACKEND_DIR / "models" / "preprocessor.pkl"

    if preprocessor_path.exists():
        log.info(f"Loading existing preprocessor from {preprocessor_path}")
        preprocessor = load_preprocessor(preprocessor_path)
    else:
        log.info("No preprocessor.pkl found — fitting from full training data.")
        X_df, _ = prepare_training_data()
        preprocessor = SecurityEventPreprocessor()
        preprocessor.fit(X_df)
        preprocessor.save(preprocessor_path)

    X_df, y = prepare_training_data()
    X_full   = preprocessor.transform(X_df)

    print(f"  Training matrix shape : {X_full.shape}")
    print(f"  Logical features      : {preprocessor.logical_feature_count}")
    print(f"  Encoded features      : {preprocessor.encoded_feature_count}")
    print(f"  Feature names         : {preprocessor.feature_names}")
    print(f"  y classes             : {y.nunique()} — {sorted(y.unique())}")
    print(f"  NaN in X              : {int(np.isnan(X_full).sum())}")
    print(f"  Inf in X              : {int(np.isinf(X_full).sum())}")

    return X_full, y, preprocessor, df_raw


# ===========================================================================
# STEP 2 — Isolation Forest training   [Phase 3 — PRESERVED UNCHANGED]
# ===========================================================================

def step_train_isolation_forest(X_full: np.ndarray):
    """Train IF on the full feature matrix (unsupervised; y never used)."""
    _header("STEP 2 — ISOLATION FOREST TRAINING")

    params = _if_params()
    print("\n  Model parameters:")
    for k, v in params.items():
        print(f"    {k:20s}: {v}")

    model = _train_if(X_full, params=params)
    print(f"\n  Training complete on {X_full.shape[0]} samples.")
    return model


# ===========================================================================
# STEP 3 — Isolation Forest evaluation   [Phase 3 — PRESERVED UNCHANGED]
# ===========================================================================

def step_evaluate_if(model, X_full: np.ndarray, y: pd.Series, df_raw: pd.DataFrame) -> dict:
    """Evaluate IF anomaly distribution. event_type shown for inspection only."""
    _header("STEP 3 — ISOLATION FOREST ANOMALY DISTRIBUTION")

    result      = predict_anomaly(model, X_full)
    labels      = result["anomaly_label"]
    scores      = result["anomaly_score"]

    n_total      = len(labels)
    n_normal     = int((labels == LABEL_NORMAL).sum())
    n_suspicious = int((labels == LABEL_SUSPICIOUS).sum())
    pct_normal   = n_normal     / n_total * 100
    pct_susp     = n_suspicious / n_total * 100
    stats        = score_statistics(scores)

    print(f"\n  Total events          : {n_total:,}")
    print(f"  Normal predictions    : {n_normal:,}  ({pct_normal:.1f}%)")
    print(f"  Suspicious predictions: {n_suspicious:,}  ({pct_susp:.1f}%)")
    print(f"\n  Score statistics (lower = more anomalous):")
    print(f"    min={stats['min']:.6f}  max={stats['max']:.6f}  "
          f"mean={stats['mean']:.6f}  median={stats['median']:.6f}  std={stats['std']:.6f}")

    susp_mask   = labels == LABEL_SUSPICIOUS
    normal_mask = labels == LABEL_NORMAL
    mean_susp   = float(scores[susp_mask].mean())   if susp_mask.any()   else float("nan")
    mean_normal = float(scores[normal_mask].mean()) if normal_mask.any() else float("nan")
    direction_ok = mean_susp < mean_normal
    print(f"\n  Direction check — Suspicious mean ({mean_susp:.5f}) < Normal mean ({mean_normal:.5f}): "
          f"{'[CORRECT]' if direction_ok else '[WARNING]'}")

    return {
        "n_total": n_total, "n_normal": n_normal, "n_suspicious": n_suspicious,
        "pct_normal": pct_normal, "pct_suspicious": pct_susp,
        "score_stats": stats, "direction_verified": direction_ok,
    }


# ===========================================================================
# STEP 4 — Save Isolation Forest   [Phase 3 — PRESERVED UNCHANGED]
# ===========================================================================

def step_save_if(model) -> Path:
    _header("STEP 4 — SAVING if_model.pkl")
    path = _save_if(model)
    size = path.stat().st_size
    print(f"  Saved to   : {path}")
    print(f"  File size  : {size:,} bytes")
    loaded = _load_if(path)
    print(f"  Reload OK  : {isinstance(loaded, type(model))}")
    return path


# ===========================================================================
# STEP 5 — Isolation Forest reproducibility   [Phase 3 — PRESERVED]
# ===========================================================================

def step_reproducibility_if(X_full: np.ndarray) -> None:
    _header("STEP 5 — IF REPRODUCIBILITY")
    params = _if_params()
    m1 = _train_if(X_full, params=params)
    m2 = _train_if(X_full, params=params)
    r1 = predict_anomaly(m1, X_full)
    r2 = predict_anomaly(m2, X_full)
    s_ok = np.allclose(r1["anomaly_score"], r2["anomaly_score"])
    l_ok = np.array_equal(r1["anomaly_label"], r2["anomaly_label"])
    print(f"  Scores identical: {s_ok}  Labels identical: {l_ok}")
    print(f"  {'[PASS] IF reproducibility confirmed.' if (s_ok and l_ok) else '[WARNING] Non-reproducible results.'}")


# ===========================================================================
# STEP 6 — Dataset validation for Random Forest
# ===========================================================================

def step_validate_dataset(y: pd.Series) -> None:
    """Verify and report actual class distribution before RF training."""
    _header("STEP 6 — DATASET CLASS DISTRIBUTION VALIDATION")

    counts = y.value_counts().sort_index()
    n_total = len(y)
    print(f"\n  Total records : {n_total:,}")
    print(f"  Num classes   : {y.nunique()}")
    print(f"\n  {'event_type':30s} | {'count':>6} | {'pct':>6} | {'min/max flag'}")
    print(f"  {SEP2}")
    min_cls, max_cls = counts.min(), counts.max()
    for cls, cnt in counts.items():
        flag = " <- MIN" if cnt == min_cls else (" <- MAX" if cnt == max_cls else "")
        print(f"  {cls:30s} | {cnt:>6} | {cnt/n_total*100:>5.1f}% |{flag}")
    print(f"\n  Min class size : {min_cls}")
    print(f"  Max class size : {max_cls}")
    ratio = max_cls / min_cls
    print(f"  Imbalance ratio: {ratio:.2f}x  "
          f"({'balanced — no reweighting needed' if ratio < 1.5 else 'consider class_weight=balanced'})")


# ===========================================================================
# STEP 7 — Train/test split
# ===========================================================================

def step_split(
    X_full: np.ndarray,
    y: pd.Series,
    df_raw: pd.DataFrame,
    preprocessor: SecurityEventPreprocessor,
) -> tuple:
    """
    80/20 stratified split with leakage-free preprocessing.

    IMPORTANT — preprocessing integrity:
      The preprocessor.pkl was fitted on the full dataset (production deployment
      assumption). For honest evaluation, we must not use test-set data to fit
      any transformation.

      Approach taken:
        1. Split the RAW feature DataFrame (X_df — pre-encoding) 80/20.
        2. Fit a fresh LOCAL preprocessor on X_train_df only.
        3. Apply that locally-fitted preprocessor to both X_train_df and X_test_df.
        4. This ensures test rows never influence encoder fit.

      The production preprocessor.pkl (fitted on full data) is used for
      live /predict inference and is NOT used here for test-set evaluation.

    Returns: (X_tr, X_te, y_tr, y_te, idx_te, local_preprocessor)
    """
    _header("STEP 7 — TRAIN/TEST SPLIT (80/20 STRATIFIED)")

    # Re-obtain the logical-feature DataFrame (before encoding)
    df_engineered = engineer_features_batch(df_raw)
    X_df = df_engineered[LOGICAL_FEATURES].copy()
    y_arr = y.values

    # Stratified split on raw X_df (pre-encoding)
    idx = np.arange(len(X_df))
    idx_tr, idx_te = train_test_split(
        idx,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y_arr,
    )

    X_df_tr = X_df.iloc[idx_tr].reset_index(drop=True)
    X_df_te = X_df.iloc[idx_te].reset_index(drop=True)
    y_tr    = y_arr[idx_tr]
    y_te    = y_arr[idx_te]

    # Fit a LOCAL preprocessor on training split only (leakage-free evaluation)
    local_preprocessor = SecurityEventPreprocessor()
    local_preprocessor.fit(X_df_tr)

    X_tr = local_preprocessor.transform(X_df_tr)
    X_te = local_preprocessor.transform(X_df_te)

    print(f"\n  Split random_state : {RANDOM_STATE}")
    print(f"  Train rows         : {len(X_tr):,}  ({len(X_tr)/len(X_df)*100:.0f}%)")
    print(f"  Test rows          : {len(X_te):,}  ({len(X_te)/len(X_df)*100:.0f}%)")
    print(f"  Train X shape      : {X_tr.shape}")
    print(f"  Test X shape       : {X_te.shape}")
    print(f"  Train class dist   : { {c: int((y_tr==c).sum()) for c in sorted(set(y_tr))} }")
    print(f"  Test class dist    : { {c: int((y_te==c).sum()) for c in sorted(set(y_te))} }")
    print(f"\n  NOTE: Local preprocessor fitted on train split only (no test leakage).")

    return X_tr, X_te, y_tr, y_te, idx_te, local_preprocessor


# ===========================================================================
# STEP 8 — Train Random Forest
# ===========================================================================

def step_train_random_forest(X_tr: np.ndarray, y_tr: np.ndarray):
    """Train RF classifier on the training split."""
    _header("STEP 8 — RANDOM FOREST TRAINING")

    params = _rf_params()
    print("\n  Model parameters:")
    for k, v in params.items():
        print(f"    {k:20s}: {v}")

    # CONFIRMED: event_type is in y_tr (target), NOT in X_tr (features)
    model = _train_rf(X_tr, y_tr, params=params)
    print(f"\n  Training complete — {X_tr.shape[0]:,} samples, "
          f"{X_tr.shape[1]} features, {len(set(y_tr))} classes.")
    return model


# ===========================================================================
# STEP 9 — Evaluate Random Forest
# ===========================================================================

def step_evaluate_rf(
    model,
    X_tr: np.ndarray,
    X_te: np.ndarray,
    y_tr: np.ndarray,
    y_te: np.ndarray,
    df_raw: pd.DataFrame,
    idx_te: np.ndarray,
    local_preprocessor: SecurityEventPreprocessor,
) -> dict:
    """Full RF evaluation on held-out test set."""
    _header("STEP 9 — RANDOM FOREST EVALUATION")

    y_pred  = model.predict(X_te)
    y_proba = model.predict_proba(X_te)
    classes = list(model.classes_)

    # Core metrics
    acc = accuracy_score(y_te, y_pred)
    report_dict = classification_report(
        y_te, y_pred, target_names=classes, output_dict=True, zero_division=0
    )
    report_str  = classification_report(
        y_te, y_pred, target_names=classes, zero_division=0
    )
    cm = confusion_matrix(y_te, y_pred, labels=classes)

    print(f"\n  Test set accuracy : {acc:.4f}  ({acc*100:.2f}%)")
    print(f"\n  Classification Report:\n")
    for line in report_str.strip().split("\n"):
        print(f"    {line}")

    # Confusion matrix
    print(f"\n  Confusion Matrix (rows=actual, cols=predicted):")
    col_width = max(len(c) for c in classes) + 2
    header_row = "  " + " " * col_width + " ".join(f"{c[:8]:>8}" for c in classes)
    print(header_row)
    for i, cls in enumerate(classes):
        row_str = "  " + f"{cls[:col_width-1]:{col_width-1}s}" + " ".join(f"{v:>8}" for v in cm[i])
        print(row_str)

    # Feature importances — mapped to encoded feature names
    print(f"\n  FEATURE IMPORTANCES (encoded, 16 columns):")
    print(f"  NOTE: These are ENCODED column importances, not logical feature importances.")
    print(f"  'protocol' logical feature is represented by 5 OHE columns below.\n")
    importances = feature_importances_report(model, local_preprocessor.feature_names)
    print(f"  {'rank':>4} | {'encoded feature':30s} | {'importance':>10}")
    print(f"  {'-'*55}")
    for item in importances:
        print(f"  {item['rank']:>4} | {item['feature']:30s} | {item['importance']:>10.6f}")

    # predict_proba validation
    print(f"\n  PREDICT_PROBA VALIDATION:")
    prob_sums = y_proba.sum(axis=1)
    all_sum_to_one = np.allclose(prob_sums, 1.0, atol=1e-6)
    print(f"    All probability rows sum to 1.0: {all_sum_to_one}  {'[PASS]' if all_sum_to_one else '[FAIL]'}")
    print(f"    Prob sum range: [{prob_sums.min():.8f}, {prob_sums.max():.8f}]")

    # Representative predictions from test set
    print(f"\n  REPRESENTATIVE TEST-SET PREDICTIONS (10 samples):")
    print(f"  NOTE: event_id/event_type shown for inspection only — not model inputs.\n")
    test_event_ids   = df_raw["event_id"].values[idx_te]
    test_event_types = df_raw["event_type"].values[idx_te]

    df_repr = pd.DataFrame({
        "event_id":    test_event_ids,
        "actual":      y_te,
        "predicted":   y_pred,
        "top_prob":    y_proba.max(axis=1),
    })
    # Show 5 correct + 5 misclassified (if any)
    correct   = df_repr[df_repr["actual"] == df_repr["predicted"]].head(5)
    incorrect = df_repr[df_repr["actual"] != df_repr["predicted"]].head(5)
    samples   = pd.concat([correct, incorrect]).drop_duplicates().head(10)

    col_w = 28
    print(f"  {'event_id':12s} | {'actual':>{col_w}} | {'predicted':>{col_w}} | {'top_prob':>9} | {'correct':>7}")
    print(f"  {'-'*90}")
    for _, row in samples.iterrows():
        ok = "YES" if row["actual"] == row["predicted"] else "NO "
        print(
            f"  {str(row['event_id']):12s} | {str(row['actual']):>{col_w}} | "
            f"{str(row['predicted']):>{col_w}} | {float(row['top_prob']):>9.4f} | {ok:>7}"
        )

    # Full probability distribution for first representative sample
    if len(samples) > 0:
        first_idx = samples.index[0]
        print(f"\n  Full probability distribution for first sample ({df_repr.loc[first_idx, 'event_id']}):")
        print(f"  {'class':30s} | {'probability':>11}")
        print(f"  {'-'*45}")
        row_probs = y_proba[first_idx]
        for cls, prob in sorted(zip(classes, row_probs), key=lambda x: -x[1]):
            print(f"  {cls:30s} | {prob:>11.6f}")

    return {
        "accuracy":           acc,
        "macro_precision":    report_dict["macro avg"]["precision"],
        "macro_recall":       report_dict["macro avg"]["recall"],
        "macro_f1":           report_dict["macro avg"]["f1-score"],
        "weighted_precision": report_dict["weighted avg"]["precision"],
        "weighted_recall":    report_dict["weighted avg"]["recall"],
        "weighted_f1":        report_dict["weighted avg"]["f1-score"],
        "proba_valid":        all_sum_to_one,
    }


# ===========================================================================
# STEP 10 — Save Random Forest artifact
# ===========================================================================

def step_save_rf(model) -> Path:
    _header("STEP 10 — SAVING clf_model.pkl")
    path = _save_rf(model)
    size = path.stat().st_size
    print(f"  Saved to   : {path}")
    print(f"  File size  : {size:,} bytes")
    loaded = _load_rf(path)
    print(f"  Reload OK  : {isinstance(loaded, type(model))}")
    return path


# ===========================================================================
# STEP 11 — RF reproducibility + reload validation
# ===========================================================================

def step_reproducibility_rf(
    X_tr: np.ndarray,
    X_te: np.ndarray,
    y_tr: np.ndarray,
    clf_path: Path,
) -> None:
    _header("STEP 11 — RF REPRODUCIBILITY & RELOAD VALIDATION")

    params = _rf_params()

    # Two independent training runs
    m1 = _train_rf(X_tr, y_tr, params=params)
    m2 = _train_rf(X_tr, y_tr, params=params)

    pred1 = m1.predict(X_te)
    pred2 = m2.predict(X_te)
    prob1 = m1.predict_proba(X_te)
    prob2 = m2.predict_proba(X_te)

    preds_identical = np.array_equal(pred1, pred2)
    probs_identical = np.allclose(prob1, prob2, atol=1e-10)
    print(f"\n  Predictions identical (2 runs): {preds_identical}  {'[PASS]' if preds_identical else '[FAIL]'}")
    print(f"  Probabilities identical (2 runs): {probs_identical}  {'[PASS]' if probs_identical else '[FAIL]'}")

    # Reload validation
    loaded_clf = _load_rf(clf_path)
    pred_loaded = loaded_clf.predict(X_te)
    prob_loaded = loaded_clf.predict_proba(X_te)
    reload_preds_ok = np.array_equal(pred1, pred_loaded)
    reload_probs_ok = np.allclose(prob1, prob_loaded, atol=1e-10)
    print(f"\n  Predictions before reload == after reload: {reload_preds_ok}  {'[PASS]' if reload_preds_ok else '[FAIL]'}")
    print(f"  Probabilities before reload approx after reload: {reload_probs_ok}  {'[PASS]' if reload_probs_ok else '[FAIL]'}")


# ===========================================================================
# Main entry point
# ===========================================================================

def main() -> None:
    print(SEP)
    print("M2 MODEL TRAINING — Isolation Forest + Random Forest")
    print("Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine")
    print(SEP)

    # Phase 3 — IF (preserved)
    X_full, y, preprocessor, df_raw = step_prepare_data()
    if_model  = step_train_isolation_forest(X_full)
    if_metrics = step_evaluate_if(if_model, X_full, y, df_raw)
    if_path   = step_save_if(if_model)
    step_reproducibility_if(X_full)

    # Phase 4 — RF
    step_validate_dataset(y)
    X_tr, X_te, y_tr, y_te, idx_te, local_pp = step_split(X_full, y, df_raw, preprocessor)
    rf_model   = step_train_random_forest(X_tr, y_tr)
    rf_metrics = step_evaluate_rf(rf_model, X_tr, X_te, y_tr, y_te, df_raw, idx_te, local_pp)
    clf_path   = step_save_rf(rf_model)
    step_reproducibility_rf(X_tr, X_te, y_tr, clf_path)

    _header("ALL TRAINING COMPLETE")
    print(f"  if_model.pkl  : {if_path}  ({if_path.stat().st_size:,} bytes)")
    print(f"  clf_model.pkl : {clf_path}  ({clf_path.stat().st_size:,} bytes)")
    print(f"\n  IF  — Normal: {if_metrics['n_normal']:,} ({if_metrics['pct_normal']:.1f}%)  "
          f"Suspicious: {if_metrics['n_suspicious']:,} ({if_metrics['pct_suspicious']:.1f}%)")
    print(f"  RF  — Accuracy: {rf_metrics['accuracy']*100:.2f}%  "
          f"Macro-F1: {rf_metrics['macro_f1']:.4f}  "
          f"Weighted-F1: {rf_metrics['weighted_f1']:.4f}")
    print(SEP)


if __name__ == "__main__":
    main()
