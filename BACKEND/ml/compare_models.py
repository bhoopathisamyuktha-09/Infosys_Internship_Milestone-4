"""
ml/compare_models.py — Offline Model Comparison Script
======================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

This script evaluates Random Forest against Logistic Regression 
on the identical train/test split (80/20) for Phase 2 validation.

Outputs to console:
  - Accuracy & Macro-F1 comparison
  - Confusion Matrix for Random Forest
"""

import sys
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

# Ensure BACKEND/ is on the path when run directly
_BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BACKEND_DIR))

from ml.preprocessing import (
    prepare_training_data,
    SecurityEventPreprocessor,
    engineer_features_batch,
    LOGICAL_FEATURES,
    load_training_dataframe
)

RANDOM_STATE = 42

def main():
    print("=================================================================")
    print("MODEL COMPARISON (Random Forest vs Logistic Regression)")
    print("=================================================================")

    df_raw = load_training_dataframe()
    X_df, y = prepare_training_data()
    y_arr = y.values

    # Step 1: Same stratified split
    df_engineered = engineer_features_batch(df_raw)
    X_logical = df_engineered[LOGICAL_FEATURES].copy()
    
    idx = np.arange(len(X_logical))
    idx_tr, idx_te = train_test_split(
        idx,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y_arr,
    )

    X_df_tr = X_logical.iloc[idx_tr].reset_index(drop=True)
    X_df_te = X_logical.iloc[idx_te].reset_index(drop=True)
    y_tr    = y_arr[idx_tr]
    y_te    = y_arr[idx_te]

    # Step 2: Fit local preprocessor
    local_pp = SecurityEventPreprocessor()
    local_pp.fit(X_df_tr)

    X_tr = local_pp.transform(X_df_tr)
    X_te = local_pp.transform(X_df_te)

    # Step 3: Train Models
    print("\nTraining Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=15, random_state=RANDOM_STATE)
    rf.fit(X_tr, y_tr)

    print("Training Logistic Regression...")
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=RANDOM_STATE))
    lr.fit(X_tr, y_tr)

    # Step 4: Evaluate
    print("\n--- RESULTS ---")
    classes = list(rf.classes_)

    # Random Forest
    rf_pred = rf.predict(X_te)
    rf_acc = accuracy_score(y_te, rf_pred)
    rf_rep = classification_report(y_te, rf_pred, target_names=classes, output_dict=True, zero_division=0)

    # Logistic Regression
    lr_pred = lr.predict(X_te)
    lr_acc = accuracy_score(y_te, lr_pred)
    lr_rep = classification_report(y_te, lr_pred, target_names=classes, output_dict=True, zero_division=0)

    print(f"\nRandom Forest Classifier:")
    print(f"  Test Accuracy   : {rf_acc*100:.2f}%")
    print(f"  Macro Precision : {rf_rep['macro avg']['precision']*100:.2f}%")
    print(f"  Macro Recall    : {rf_rep['macro avg']['recall']*100:.2f}%")
    print(f"  Macro F1-Score  : {rf_rep['macro avg']['f1-score']*100:.2f}%")

    print(f"\nLogistic Regression:")
    print(f"  Test Accuracy   : {lr_acc*100:.2f}%")
    print(f"  Macro Precision : {lr_rep['macro avg']['precision']*100:.2f}%")
    print(f"  Macro Recall    : {lr_rep['macro avg']['recall']*100:.2f}%")
    print(f"  Macro F1-Score  : {lr_rep['macro avg']['f1-score']*100:.2f}%")

    print("\nRandom Forest Confusion Matrix:")
    rf_cm = confusion_matrix(y_te, rf_pred, labels=classes)
    col_width = max(len(c) for c in classes) + 2
    header_row = "  " + " " * col_width + " ".join(f"{c[:8]:>8}" for c in classes)
    print(header_row)
    for i, cls in enumerate(classes):
        row_str = "  " + f"{cls[:col_width-1]:{col_width-1}s}" + " ".join(f"{v:>8}" for v in rf_cm[i])
        print(row_str)
        
    print("\nLogistic Regression Confusion Matrix:")
    lr_cm = confusion_matrix(y_te, lr_pred, labels=classes)
    header_row = "  " + " " * col_width + " ".join(f"{c[:8]:>8}" for c in classes)
    print(header_row)
    for i, cls in enumerate(classes):
        row_str = "  " + f"{cls[:col_width-1]:{col_width-1}s}" + " ".join(f"{v:>8}" for v in lr_cm[i])
        print(row_str)

if __name__ == "__main__":
    main()
