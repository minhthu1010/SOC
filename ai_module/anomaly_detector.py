"""
anomaly_detector.py – Isolation Forest–based UEBA Anomaly Detector
===================================================================
Wraps scikit-learn's IsolationForest with:
  • Automatic feature scaling (RobustScaler)
  • Model persistence (joblib)
  • Per-prediction behaviour explanation
  • Wazuh alert injection for detected anomalies
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.preprocessing import RobustScaler

from .feature_extractor import FEATURE_COLUMNS

logger = logging.getLogger(__name__)

# ── Default hyper-parameters ───────────────────────────────────────────────────
DEFAULT_CONTAMINATION  = 0.05   # expected fraction of anomalies in training data
DEFAULT_N_ESTIMATORS   = 200
DEFAULT_MAX_SAMPLES    = "auto"
DEFAULT_RANDOM_STATE   = 42

# Path where Wazuh reads AI alerts (localfile block in ossec.conf)
WAZUH_AI_ALERT_LOG = os.environ.get(
    "WAZUH_AI_ALERT_LOG",
    "/var/ossec/logs/ai_alerts.log",
)


# ──────────────────────────────────────────────────────────────────────────────
class UEBADetector:
    """Isolation Forest anomaly detector for User and Entity Behaviour Analytics.

    Usage
    -----
    >>> detector = UEBADetector()
    >>> detector.train(train_df)
    >>> results = detector.predict(live_df)
    >>> detector.save("/opt/soc/models/ueba_model.joblib")
    >>> detector2 = UEBADetector.load("/opt/soc/models/ueba_model.joblib")
    """

    def __init__(
        self,
        contamination: float = DEFAULT_CONTAMINATION,
        n_estimators: int = DEFAULT_N_ESTIMATORS,
        max_samples: str | int = DEFAULT_MAX_SAMPLES,
        random_state: int = DEFAULT_RANDOM_STATE,
    ) -> None:
        self.contamination = contamination
        self.n_estimators  = n_estimators
        self.max_samples   = max_samples
        self.random_state  = random_state

        self._scaler: RobustScaler | None = None
        self._model:  IsolationForest | None = None
        self._threshold: float = 0.0  # anomaly score threshold (negative)

    # ── Training ──────────────────────────────────────────────────────────────
    def train(
        self,
        df: pd.DataFrame,
        label_column: str | None = None,
    ) -> "UEBADetector":
        """Fit the scaler and Isolation Forest on *df*.

        Parameters
        ----------
        df:
            DataFrame with at minimum the columns in FEATURE_COLUMNS.
        label_column:
            If provided, only *normal* rows (label == 0) are used for fitting
            (semi-supervised mode).  If None, all rows are used.
        """
        X = self._select_features(df)

        if label_column and label_column in df.columns:
            X_train = X[df[label_column] == 0]
            logger.info("Training on %d normal samples (semi-supervised).", len(X_train))
        else:
            X_train = X
            logger.info("Training on all %d samples (unsupervised).", len(X_train))

        self._scaler = RobustScaler()
        X_scaled = self._scaler.fit_transform(X_train)

        self._model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)
        self._threshold = self._model.offset_
        logger.info("Model trained. Decision threshold: %.4f", self._threshold)
        return self

    # ── Prediction ────────────────────────────────────────────────────────────
    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Score rows in *df* and return an enriched DataFrame.

        Added columns
        -------------
        ai_score      : raw anomaly score (negative = more anomalous)
        ai_prediction : 1 = anomaly, 0 = normal  (-1/+1 from sklearn → mapped)
        ai_behaviours : list of triggered behaviour descriptions
        """
        self._check_fitted()
        X = self._select_features(df)
        X_scaled = self._scaler.transform(X)

        scores      = self._model.score_samples(X_scaled)   # negative = anomalous
        predictions = self._model.predict(X_scaled)          # -1 = anomaly, +1 = normal

        result = df.copy()
        result["ai_score"]      = scores
        result["ai_prediction"] = (predictions == -1).astype(int)
        result["ai_behaviours"] = [
            self._explain(row, score)
            for row, score in zip(df.itertuples(index=False), scores)
        ]
        return result

    # ── Evaluation ────────────────────────────────────────────────────────────
    def evaluate(self, df: pd.DataFrame, label_column: str = "label") -> dict[str, Any]:
        """Compute evaluation metrics against ground-truth labels."""
        self._check_fitted()
        if label_column not in df.columns:
            raise ValueError(f"Label column '{label_column}' not in DataFrame.")
        result = self.predict(df)
        y_true = df[label_column].values
        y_pred = result["ai_prediction"].values
        y_score = -result["ai_score"].values  # flip so higher = more anomalous

        report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
        try:
            auc = roc_auc_score(y_true, y_score)
        except ValueError:
            auc = float("nan")

        metrics = {
            "roc_auc":   round(auc, 4),
            "precision": round(report.get("1", {}).get("precision", 0), 4),
            "recall":    round(report.get("1", {}).get("recall", 0), 4),
            "f1":        round(report.get("1", {}).get("f1-score", 0), 4),
            "accuracy":  round(report.get("accuracy", 0), 4),
        }
        logger.info("Evaluation results: %s", metrics)
        return metrics

    # ── Wazuh alert injection ─────────────────────────────────────────────────
    def alert_wazuh(self, result: pd.DataFrame) -> int:
        """Write anomaly rows to the Wazuh AI alert log.

        Returns the number of alerts written.
        """
        anomalies = result[result["ai_prediction"] == 1]
        if anomalies.empty:
            return 0

        log_dir = Path(WAZUH_AI_ALERT_LOG).parent
        log_dir.mkdir(parents=True, exist_ok=True)

        written = 0
        with open(WAZUH_AI_ALERT_LOG, "a") as fh:
            for _, row in anomalies.iterrows():
                alert = {
                    "ai_alert":      "isolation_forest",
                    "timestamp":     datetime.now(timezone.utc).isoformat(),
                    "user":          row.get("username", "UNKNOWN"),
                    "window":        str(row.get("window", "")),
                    "ai_score":      round(float(row["ai_score"]), 6),
                    "ai_behaviours": row.get("ai_behaviours", []),
                    "features": {
                        col: (
                            round(float(row[col]), 4) if isinstance(row[col], float)
                            else int(row[col])
                        )
                        for col in FEATURE_COLUMNS
                        if col in row.index
                    },
                }
                fh.write(json.dumps(alert) + "\n")
                written += 1

        logger.info("Wrote %d AI anomaly alert(s) to %s", written, WAZUH_AI_ALERT_LOG)
        return written

    # ── Persistence ───────────────────────────────────────────────────────────
    def save(self, path: str | Path) -> None:
        """Serialise the fitted scaler + model to a joblib file."""
        self._check_fitted()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"scaler": self._scaler, "model": self._model,
                     "threshold": self._threshold}, path)
        logger.info("Model saved: %s", path)

    @classmethod
    def load(cls, path: str | Path) -> "UEBADetector":
        """Deserialise a previously saved UEBADetector."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")
        state  = joblib.load(path)
        inst   = cls()
        inst._scaler    = state["scaler"]
        inst._model     = state["model"]
        inst._threshold = state.get("threshold", inst._model.offset_)
        logger.info("Model loaded: %s", path)
        return inst

    # ── Internal helpers ──────────────────────────────────────────────────────
    def _select_features(self, df: pd.DataFrame) -> pd.DataFrame:
        missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
        if missing:
            raise ValueError(f"Missing feature columns: {missing}")
        return df[FEATURE_COLUMNS].fillna(0).astype(float)

    def _check_fitted(self) -> None:
        if self._model is None or self._scaler is None:
            raise RuntimeError("Model not trained. Call train() first.")

    @staticmethod
    def _explain(row: Any, score: float) -> list[str]:
        """Return human-readable descriptions of suspicious behaviours."""
        behaviours: list[str] = []
        try:
            if getattr(row, "login_count", 0) > 20:
                behaviours.append("high_login_frequency")
            if getattr(row, "failed_login_count", 0) > 10:
                behaviours.append("many_failed_logins")
            if getattr(row, "unique_hosts", 0) > 5:
                behaviours.append("high_host_count")
            if getattr(row, "resource_access_count", 0) > 30:
                behaviours.append("high_resource_access")
            if getattr(row, "after_hours_logins", 0) > 3:
                behaviours.append("after_hours_activity")
            if getattr(row, "unusual_logon_type_count", 0) > 2:
                behaviours.append("unusual_logon_type")
            if getattr(row, "max_hosts_per_10min", 0) > 3:
                behaviours.append("lateral_movement_spike")
        except AttributeError:
            pass
        if not behaviours:
            behaviours.append("statistical_outlier")
        return behaviours
