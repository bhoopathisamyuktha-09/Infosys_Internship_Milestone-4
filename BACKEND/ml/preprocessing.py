"""
ml/preprocessing.py — M2 Feature Engineering & Preprocessing Pipeline
=======================================================================
Milestone 2: AI-Based Threat Detection & Anomaly Analysis Engine

This module is the SINGLE source of truth for all feature transformations.
It is shared by:
  A. Offline model training (ml/train_models.py)
  B. Live POST /predict inference (routes/prediction_routes.py)

The fitted preprocessing artifact (models/preprocessor.pkl) is trained ONCE
offline and reused identically during inference. A new encoder/scaler is
NEVER fitted during live inference.

Feature Contract Version: 1.5.0
See: BACKEND/docs/feature_selection.md
"""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import OneHotEncoder

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration constants
# ---------------------------------------------------------------------------

# Project-heuristic threshold for impossible travel detection.
# Documented explicitly as a heuristic — not an external travel-speed standard.
# Increase this value to make the flag less sensitive; decrease for stricter detection.
IMPOSSIBLE_TRAVEL_WINDOW_HOURS: float = 4.0

# Columns that form the 12 logical features selected in the feature contract.
# These are the raw column names BEFORE one-hot encoding expands 'protocol'.
LOGICAL_FEATURES: list[str] = [
    "failed_login_attempts",  # Authentication: brute-force signal
    "status_flag",            # Authentication: outcome (0=Success/Failed, 1=Blocked/Detected)
    "cvss_score",             # Vulnerability: CVE severity score (0.0–10.0)
    "severity_score",         # Security flag: ordinal severity (1=Low … 4=Critical)
    "malware_flag",           # Security flag: malware alert binary
    "hour",                   # Time: hour of day (0–23)
    "is_weekend",             # Time: weekend indicator
    "protocol",               # Network: categorical, will be one-hot encoded
    "events_per_user",        # User behavior: derived aggregate (see Section 5.2 of contract)
    "unique_destination_count",  # Network: derived aggregate (see Section 5.2 of contract)
    "after_hours_flag",       # User behavior: derived binary (hour < 8 or hour >= 18)
    "impossible_travel_flag", # Location: derived geo-anomaly flag (see Section 5.1 of contract)
]

# Columns that must NEVER appear in the ML feature matrix X.
# Includes direct identifiers, the target label, leakage fields, and zero-variance constants.
EXCLUDED_COLUMNS: list[str] = [
    # Direct identifiers
    "event_id", "timestamp", "source_ip", "destination_ip", "username",
    # Target label (y for Random Forest, never X)
    "event_type",
    # Target-leakage fields (1-to-1 mapping from event_type)
    "technique_id", "technique_name", "tactic",
    # Post-event synthetic risk assessment fields
    "risk_level", "login_risk", "threat_confidence",
    # Zero-variance constants in M1 baseline dataset
    "source_country", "destination_country", "year", "month",
    # Other raw M1 columns not in feature contract
    "device_name", "asset_name", "department", "day_of_week",
    "day", "os", "malware_detected", "vulnerability_id",
]

# Protocol categories observed in M1 baseline dataset.
# Used only for documentation; the encoder derives categories from training data.
KNOWN_PROTOCOLS: list[str] = ["HTTP", "HTTPS", "SMB", "SSH", "TCP"]

# Default path where the fitted preprocessor artifact is saved/loaded.
_DEFAULT_PREPROCESSOR_PATH = Path(__file__).resolve().parent.parent / "models" / "preprocessor.pkl"

# Columns that require numeric scaling consideration (kept as documentation).
# Tree-based models (Isolation Forest, Random Forest) are scale-invariant,
# so StandardScaler is NOT applied. This list is retained for future reference
# if a distance/gradient model is added later.
# NUMERICAL_COLS_FOR_SCALING = [
#     "failed_login_attempts", "cvss_score", "events_per_user",
#     "unique_destination_count", "hour", "severity_score"
# ]


# ---------------------------------------------------------------------------
# Section 1: Raw data loading
# ---------------------------------------------------------------------------

def load_training_dataframe(csv_path: str | Path | None = None) -> pd.DataFrame:
    """
    Load the M1 security_events CSV for offline training.

    The CSV is read directly from disk — it is NEVER modified.
    MongoDB is NOT used during offline training batch processing.

    Args:
        csv_path: Optional override path. Defaults to BACKEND/data/security_events.csv.

    Returns:
        Raw DataFrame with all 34 M1 columns.
    """
    if csv_path is None:
        csv_path = Path(__file__).resolve().parent.parent / "data" / "security_events.csv"
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"Training CSV not found at: {csv_path}")
    df = pd.read_csv(csv_path)
    logger.info(f"Loaded training data from {csv_path}: {df.shape[0]} rows, {df.shape[1]} columns")
    return df


# ---------------------------------------------------------------------------
# Section 2: Derived feature engineering
# ---------------------------------------------------------------------------

def _derive_after_hours_flag(df: pd.DataFrame) -> pd.Series:
    """
    Derive after_hours_flag from the 'hour' column.

    Business-hours definition (project convention): 08:00 – 17:59
    Outside this window (hour < 8 OR hour >= 18) → 1
    Inside this window → 0
    """
    return ((df["hour"] < 8) | (df["hour"] >= 18)).astype(int)


def _derive_impossible_travel_flag(df: pd.DataFrame) -> pd.Series:
    """
    Derive impossible_travel_flag using the approved project heuristic.

    Algorithm (per feature_selection.md Section 5.1):
      1. Sort events chronologically per username.
      2. Compute time delta (Δt) between consecutive logins for the same user.
      3. Compare source_country of consecutive events for the same user.
      4. Flag as 1 if source_country changed AND Δt < IMPOSSIBLE_TRAVEL_WINDOW_HOURS.

    Configuration:
      IMPOSSIBLE_TRAVEL_WINDOW_HOURS = 4.0  (project heuristic, explicitly documented)

    M1 Dataset Limitation:
      In the baseline M1 CSV, source_country = 'India' for ALL 10,000 records.
      Therefore this flag evaluates to constant 0 across the training dataset.
      The trained ML models CANNOT learn a non-zero split from M1 training data alone.
      The flag remains active for:
        - Live POST /predict inference with geo-diverse event payloads.
        - Rule-based scoring boost in services/scoring_service.py.

    Args:
        df: DataFrame containing 'username', 'timestamp', 'source_country' columns.

    Returns:
        Boolean Series (int 0/1) aligned with the input DataFrame's index.
    """
    # Work on a copy to avoid modifying the caller's DataFrame
    work = df[["username", "timestamp", "source_country"]].copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"], errors="coerce")

    # Sort chronologically within each user group for sequential comparison
    work = work.sort_values(["username", "timestamp"])

    # Previous event's country and timestamp for the same user
    work["_prev_country"] = work.groupby("username")["source_country"].shift(1)
    work["_prev_ts"] = work.groupby("username")["timestamp"].shift(1)
    work["_delta_hours"] = (work["timestamp"] - work["_prev_ts"]).dt.total_seconds() / 3600.0

    # Flag: country changed AND interval is suspiciously short
    flag = (
        (work["source_country"] != work["_prev_country"])
        & work["_prev_country"].notna()
        & (work["_delta_hours"] < IMPOSSIBLE_TRAVEL_WINDOW_HOURS)
    ).astype(int)

    # Re-align to the original index (sort may have changed row order)
    flag = flag.reindex(df.index).fillna(0).astype(int)
    return flag


def _derive_temporal_features_causal(df: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    """
    Training strategy (STRICT CAUSAL):
    For each event, compute historical aggregates (events_per_user, unique_destination_count)
    using ONLY events for the same username with timestamp STRICTLY LESS THAN the current event's timestamp.
    
    This matches the live inference definition perfectly.
    Same-timestamp events do not contaminate each other.
    
    Returns:
        Tuple of (events_per_user, unique_destination_count) Series aligned with df index.
    """
    from bisect import bisect_left
    
    orig_idx = df.index
    work = df[["username", "timestamp", "destination_ip"]].copy()
    work["_parsed_dt"] = pd.to_datetime(work["timestamp"], errors="coerce")
    
    # Precompute causal prefix sets per user
    user_dts = {}
    user_prefix_sets = {}
    
    valid_work = work[work["_parsed_dt"].notna()].copy()
    valid_work = valid_work.sort_values(["username", "_parsed_dt"])
    
    for user, group in valid_work.groupby("username"):
        dts = group["_parsed_dt"].tolist()
        dests = group["destination_ip"].tolist()
        
        prefix_sets = [set()]
        curr_set = set()
        for dest in dests:
            if pd.notna(dest) and dest != "":
                curr_set.add(dest)
            prefix_sets.append(set(curr_set))
            
        user_dts[user] = dts
        user_prefix_sets[user] = prefix_sets
        
    epu_list = []
    udc_list = []
    
    for _, row in work.iterrows():
        user = row["username"]
        dt = row["_parsed_dt"]
        
        if pd.isna(dt) or user not in user_dts:
            epu_list.append(1)
            dest = row["destination_ip"]
            udc_list.append(1 if pd.notna(dest) and dest != "" else 0)
            continue
            
        # Strict causality: bisect_left finds the first index >= dt
        dts = user_dts[user]
        first_ge_idx = bisect_left(dts, dt)
        
        # History is everything before first_ge_idx
        epu = first_ge_idx + 1
        prior_dests = user_prefix_sets[user][first_ge_idx]
        
        curr_dest = row["destination_ip"]
        if pd.notna(curr_dest) and curr_dest != "":
            udc = len(prior_dests | {curr_dest})
        else:
            udc = len(prior_dests)
            
        epu_list.append(epu)
        udc_list.append(udc)
        
    return pd.Series(epu_list, index=orig_idx).astype(int), pd.Series(udc_list, index=orig_idx).astype(int)


def engineer_features_batch(df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply all feature engineering steps to a DataFrame for offline training.

    This function adds derived columns to the DataFrame in-place (on a copy).
    It does NOT select or encode features — that is handled by build_feature_matrix().

    Args:
        df: Raw M1 DataFrame loaded from security_events.csv.

    Returns:
        DataFrame with derived feature columns appended.
    """
    df = df.copy()

    # Derived feature: after_hours_flag
    df["after_hours_flag"] = _derive_after_hours_flag(df)

    # Derived feature: impossible_travel_flag
    df["impossible_travel_flag"] = _derive_impossible_travel_flag(df)

    # Derived features: events_per_user, unique_destination_count (strict causal)
    epu, udc = _derive_temporal_features_causal(df)
    df["events_per_user"] = epu
    df["unique_destination_count"] = udc

    logger.debug("Feature engineering complete: added 4 derived columns to batch DataFrame.")
    return df


def engineer_features_single_event(
    event: dict[str, Any],
    historical_events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Apply feature engineering for a SINGLE incoming event during live inference.

    Live inference strategy (per feature_selection.md Section 5.2):
      - historical_events: list of MongoDB security_events documents for the SAME username,
        with timestamps STRICTLY BEFORE the incoming event's timestamp.
        Future events must never be included to maintain temporal causality.
      - events_per_user: count of historical events + 1 (the current event).
      - unique_destination_count: nunique of destination_ip across historical events
        combined with the incoming event's destination_ip.
      - after_hours_flag: derived from the incoming event's own 'hour' field.
      - impossible_travel_flag: derived by comparing the incoming event's
        source_country against the most recent historical event's source_country
        and checking the time delta.

    Args:
        event: Dict representing the incoming event (from POST /predict payload).
        historical_events: Optional list of prior MongoDB event dicts for the same user.
                           If None or empty, aggregates default to 1 / 1.

    Returns:
        Updated copy of the event dict with derived feature keys populated.
    """
    event = dict(event)  # shallow copy to avoid mutating caller's dict
    hist = historical_events or []

    # --- after_hours_flag ---
    hour = int(event.get("hour", 0))
    event["after_hours_flag"] = 1 if (hour < 8 or hour >= 18) else 0

    # --- events_per_user (historical count + the current event itself) ---
    event["events_per_user"] = len(hist) + 1

    # --- unique_destination_count ---
    all_dest_ips = {h.get("destination_ip") for h in hist if h.get("destination_ip")}
    if event.get("destination_ip"):
        all_dest_ips.add(event["destination_ip"])
    event["unique_destination_count"] = len(all_dest_ips)

    # --- impossible_travel_flag ---
    # Find the most recent historical event for this user (by timestamp)
    impossible = 0
    if hist:
        hist_sorted = sorted(
            [h for h in hist if h.get("timestamp") and h.get("source_country")],
            key=lambda h: pd.to_datetime(h["timestamp"]),
        )
        if hist_sorted:
            last = hist_sorted[-1]
            last_country = last.get("source_country", "")
            current_country = event.get("source_country", "")
            if last_country and current_country and last_country != current_country:
                try:
                    last_ts = pd.to_datetime(last["timestamp"])
                    current_ts = pd.to_datetime(event.get("timestamp", pd.Timestamp.now()))
                    delta_hours = (current_ts - last_ts).total_seconds() / 3600.0
                    if delta_hours < IMPOSSIBLE_TRAVEL_WINDOW_HOURS:
                        impossible = 1
                except Exception:
                    impossible = 0
    event["impossible_travel_flag"] = impossible

    return event


# ---------------------------------------------------------------------------
# Section 3: Preprocessing pipeline (encoder only — no StandardScaler)
# ---------------------------------------------------------------------------

class SecurityEventPreprocessor:
    """
    Fitted preprocessing pipeline for security event ML features.

    Responsibilities:
      - One-Hot Encode the 'protocol' categorical column.
      - Select and order the final ML feature matrix columns.
      - Expose the final encoded feature names.
      - Persist itself to disk (models/preprocessor.pkl).
      - Transform new single-event payloads during live inference identically
        to how training data was transformed.

    Scaling decision:
      Both primary M2 algorithms (Isolation Forest, Random Forest) are tree-based
      and invariant to monotonic feature scaling. StandardScaler is NOT applied.
      This keeps the pipeline simple and explainable.

    Note on protocol encoding:
      OneHotEncoder is initialized with handle_unknown='ignore'. This ensures that
      if a future protocol value appears during live inference that was not present
      in training data, the encoder produces an all-zero column row rather than
      raising an error. The final encoded column count is NOT hardcoded.
    """

    def __init__(self) -> None:
        self._encoder: OneHotEncoder | None = None
        self._protocol_feature_names: list[str] = []
        self._final_feature_names: list[str] = []
        self._is_fitted: bool = False

    # ---------------------------------------------------------------
    # Numeric-only logical features (everything except 'protocol')
    # ---------------------------------------------------------------
    _NUMERIC_FEATURES: list[str] = [
        "failed_login_attempts",
        "status_flag",
        "cvss_score",
        "severity_score",
        "malware_flag",
        "hour",
        "is_weekend",
        "events_per_user",
        "unique_destination_count",
        "after_hours_flag",
        "impossible_travel_flag",
    ]

    def fit(self, df: pd.DataFrame) -> "SecurityEventPreprocessor":
        """
        Fit the preprocessor on the training DataFrame.

        Must be called ONCE on training data before transform() or save().
        The fitted encoder configuration is retained so that the exact same
        column ordering and category mapping is applied during inference.

        Args:
            df: DataFrame that has already had derived features engineered
                (i.e., engineer_features_batch() has been applied).

        Returns:
            self (for method chaining)
        """
        if "protocol" not in df.columns:
            raise ValueError("Training DataFrame must contain 'protocol' column.")

        self._encoder = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
        protocol_values = df[["protocol"]]
        self._encoder.fit(protocol_values)
        self._protocol_feature_names = list(self._encoder.get_feature_names_out(["protocol"]))

        # Final feature names = numeric features + encoded protocol columns
        self._final_feature_names = self._NUMERIC_FEATURES + self._protocol_feature_names
        self._is_fitted = True
        logger.info(
            f"Preprocessor fitted. Logical features: {len(LOGICAL_FEATURES)}, "
            f"Encoded matrix columns: {len(self._final_feature_names)} "
            f"({len(self._NUMERIC_FEATURES)} numeric + {len(self._protocol_feature_names)} protocol OHE)"
        )
        return self

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Transform a DataFrame into the ML-ready feature matrix X.

        Applies one-hot encoding to 'protocol' and selects/orders all features
        consistently with the training configuration. Numeric features are passed
        through unchanged (no scaling — tree-based models are scale-invariant).

        Args:
            df: DataFrame with all LOGICAL_FEATURES columns present (derived features
                must have been computed before calling transform).

        Returns:
            numpy ndarray of shape (n_rows, N_encoded_columns).

        Raises:
            RuntimeError: if fit() has not been called first.
        """
        self._assert_fitted()
        self._validate_input_columns(df)

        # Numeric block (scale-invariant; passed through as-is)
        numeric_block = df[self._NUMERIC_FEATURES].copy()
        numeric_block = numeric_block.fillna(0)  # Explicit missing-value handling

        # Ensure is_weekend is integer (M1 CSV stores it as bool)
        numeric_block["is_weekend"] = numeric_block["is_weekend"].astype(int)
        numeric_arr = numeric_block.values.astype(float)

        # One-hot encoded protocol block
        protocol_block = df[["protocol"]].fillna("Unknown")
        protocol_arr = self._encoder.transform(protocol_block)

        # Concatenate: numeric columns first, then OHE protocol columns
        X = np.hstack([numeric_arr, protocol_arr])
        return X

    def transform_single(self, event: dict[str, Any]) -> np.ndarray:
        """
        Transform a single event dict into a (1, N) feature matrix for inference.

        The event dict must already have derived features populated by
        engineer_features_single_event() before calling this method.

        Args:
            event: Dict with all required feature keys.

        Returns:
            numpy ndarray of shape (1, N_encoded_columns).
        """
        df = pd.DataFrame([event])
        return self.transform(df)

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        """
        Convenience method: fit then transform the training DataFrame.

        Args:
            df: Engineered training DataFrame.

        Returns:
            numpy ndarray X_train.
        """
        return self.fit(df).transform(df)

    @property
    def feature_names(self) -> list[str]:
        """
        Return the ordered list of final encoded feature column names.

        This is the canonical column ordering of the ML feature matrix.
        Must be consistent between training and inference.
        """
        self._assert_fitted()
        return list(self._final_feature_names)

    @property
    def logical_feature_count(self) -> int:
        """Number of logical/domain features (before OHE expansion)."""
        return len(LOGICAL_FEATURES)

    @property
    def encoded_feature_count(self) -> int:
        """Number of actual columns in the encoded ML matrix X."""
        self._assert_fitted()
        return len(self._final_feature_names)

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def save(self, path: str | Path | None = None) -> Path:
        """
        Persist the fitted preprocessor to disk using joblib.

        Args:
            path: Optional override path. Defaults to models/preprocessor.pkl.

        Returns:
            Path where the artifact was saved.
        """
        self._assert_fitted()
        save_path = Path(path) if path else _DEFAULT_PREPROCESSOR_PATH
        save_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, save_path)
        logger.info(f"Preprocessor artifact saved to: {save_path}")
        return save_path

    def _assert_fitted(self) -> None:
        if not self._is_fitted:
            raise RuntimeError(
                "SecurityEventPreprocessor has not been fitted. "
                "Call fit() or load_preprocessor() before transform()."
            )

    def _validate_input_columns(self, df: pd.DataFrame) -> None:
        """Warn if expected logical features are missing from the input DataFrame."""
        missing = [col for col in LOGICAL_FEATURES if col not in df.columns]
        if missing:
            raise ValueError(
                f"Input DataFrame is missing required feature columns: {missing}. "
                f"Ensure engineer_features_batch() or engineer_features_single_event() "
                f"has been applied before calling transform()."
            )


# ---------------------------------------------------------------------------
# Section 4: Artifact persistence helpers
# ---------------------------------------------------------------------------

def load_preprocessor(path: str | Path | None = None) -> SecurityEventPreprocessor:
    """
    Load a previously fitted SecurityEventPreprocessor from disk.

    Called at FastAPI startup via model_loader.py to make the preprocessor available
    for live inference without refitting. Must be called AFTER the preprocessor has
    been trained and saved via train_models.py.

    Args:
        path: Optional override path. Defaults to models/preprocessor.pkl.

    Returns:
        Loaded SecurityEventPreprocessor instance.

    Raises:
        FileNotFoundError: if the artifact file does not exist.
    """
    load_path = Path(path) if path else _DEFAULT_PREPROCESSOR_PATH
    if not load_path.exists():
        raise FileNotFoundError(
            f"Preprocessor artifact not found at: {load_path}. "
            f"Run 'python ml/train_models.py' to generate it."
        )
    preprocessor: SecurityEventPreprocessor = joblib.load(load_path)
    if not isinstance(preprocessor, SecurityEventPreprocessor):
        raise TypeError(
            f"Loaded object at {load_path} is not a SecurityEventPreprocessor instance."
        )
    logger.info(f"Preprocessor loaded from: {load_path} — {preprocessor.encoded_feature_count} encoded features")
    return preprocessor


# ---------------------------------------------------------------------------
# Section 5: High-level convenience entry-points
# ---------------------------------------------------------------------------

def prepare_training_data(csv_path: str | Path | None = None) -> tuple[pd.DataFrame, pd.Series]:
    """
    Full pipeline: load M1 CSV → engineer features → return (X_df, y).

    X_df contains all logical feature columns (including derived ones) before encoding.
    y contains the event_type target labels for Random Forest supervised training.

    Note: X_df is NOT yet encoded. Call preprocessor.fit_transform(X_df) next.

    Args:
        csv_path: Optional path override for security_events.csv.

    Returns:
        Tuple (X_df, y):
          X_df: DataFrame with derived features, 12 logical columns.
          y:    Series of event_type labels (the RF classifier target).
    """
    df_raw = load_training_dataframe(csv_path)
    df_engineered = engineer_features_batch(df_raw)

    # Verify no missing values in selected logical features (excluding 'protocol')
    numeric_check = [c for c in SecurityEventPreprocessor._NUMERIC_FEATURES if c in df_engineered.columns]
    missing_summary = df_engineered[numeric_check].isnull().sum()
    if missing_summary.any():
        logger.warning(f"Missing values detected in ML features before encoding:\n{missing_summary[missing_summary > 0]}")

    # Target label
    y = df_engineered["event_type"]

    # Select only the 12 logical feature columns for the X matrix
    X_df = df_engineered[LOGICAL_FEATURES].copy()

    logger.info(
        f"Training data prepared: {X_df.shape[0]} rows, "
        f"{len(LOGICAL_FEATURES)} logical features, target classes: {y.nunique()}"
    )
    return X_df, y
