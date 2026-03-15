"""
dataset_builder.py – Hybrid Dataset Construction
==================================================
Combines:
  • CERT r4.2 dataset (CSV with user behaviour records)
  • Lab Dataset       (Wazuh JSONL alerts from the lab environment)

into a unified Pandas DataFrame ready for training / evaluation.

CERT r4.2 column mapping
------------------------
The public CERT r4.2 dataset contains the following relevant columns:
  id, date, user, pc, activity, details

We project them onto our unified feature schema.

Lab Dataset
-----------
Raw Wazuh JSONL alerts as exported by the manager.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .feature_extractor import (
    FEATURE_COLUMNS,
    build_feature_vectors,
    load_events_from_file,
)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# CERT r4.2 helpers
# ──────────────────────────────────────────────────────────────────────────────

_CERT_ACTIVITY_MAP: dict[str, dict] = {
    "Logon":       {"event_id": "4624", "logon_type": "2",  "success": True},
    "Logoff":      {"event_id": "4634", "logon_type": "0",  "success": True},
    "Device":      {"event_id": "5140", "logon_type": "3",  "success": True},
    "Email":       {"event_id": "5145", "logon_type": "3",  "success": True},
    "File":        {"event_id": "5145", "logon_type": "3",  "success": True},
    "HTTP":        {"event_id": "5145", "logon_type": "3",  "success": True},
}


def _map_cert_row(row: pd.Series) -> dict[str, Any] | None:
    """Convert a CERT r4.2 row to our internal event schema."""
    activity = str(row.get("activity", "")).strip()
    mapping  = _CERT_ACTIVITY_MAP.get(activity)
    if mapping is None:
        return None
    try:
        ts = pd.to_datetime(row["date"], utc=True)
    except Exception:
        return None
    return {
        "timestamp":   ts,
        "username":    str(row.get("user", "UNKNOWN")).upper(),
        "event_id":    mapping["event_id"],
        "logon_type":  mapping["logon_type"],
        "workstation": str(row.get("pc", "UNKNOWN")).upper(),
        "ip_address":  "",
        "share_name":  "",
        "success":     mapping["success"],
        "source":      "cert",
    }


def load_cert_dataset(csv_path: str | Path) -> list[dict[str, Any]]:
    """Load the CERT r4.2 CSV and return a list of normalised event dicts."""
    csv_path = Path(csv_path)
    if not csv_path.exists():
        logger.warning("CERT dataset not found: %s", csv_path)
        return []

    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = [c.lower() for c in df.columns]
    # Older CERT versions use 'date' or 'timestamp'
    if "date" not in df.columns and "timestamp" in df.columns:
        df.rename(columns={"timestamp": "date"}, inplace=True)

    events: list[dict[str, Any]] = []
    for _, row in df.iterrows():
        ev = _map_cert_row(row)
        if ev:
            events.append(ev)
    logger.info("Loaded %d events from CERT dataset: %s", len(events), csv_path)
    return events


# ──────────────────────────────────────────────────────────────────────────────
# Hybrid dataset builder
# ──────────────────────────────────────────────────────────────────────────────

def build_hybrid_dataset(
    cert_csv_path: str | Path | None = None,
    lab_jsonl_path: str | Path | None = None,
    window_minutes: int = 60,
    label_column: str = "label",
) -> pd.DataFrame:
    """Build a hybrid feature dataset from CERT r4.2 and/or lab JSONL events.

    Parameters
    ----------
    cert_csv_path:
        Path to the CERT r4.2 CSV file (optional).
    lab_jsonl_path:
        Path to the Wazuh JSONL alert export (optional).
    window_minutes:
        Aggregation window size in minutes.
    label_column:
        Name of the output label column (1 = anomaly, 0 = normal).
        Labels are inferred where possible; otherwise default to 0.

    Returns
    -------
    pd.DataFrame with FEATURE_COLUMNS + [label_column].
    """
    all_events: list[dict[str, Any]] = []

    if cert_csv_path:
        cert_events = load_cert_dataset(cert_csv_path)
        for ev in cert_events:
            ev.setdefault("source", "cert")
        all_events.extend(cert_events)

    if lab_jsonl_path:
        lab_events = load_events_from_file(lab_jsonl_path)
        for ev in lab_events:
            ev.setdefault("source", "lab")
        all_events.extend(lab_events)

    if not all_events:
        logger.warning("No events loaded – returning empty DataFrame.")
        return pd.DataFrame(columns=FEATURE_COLUMNS + [label_column])

    feature_df = build_feature_vectors(all_events, window_minutes=window_minutes)

    # ── Heuristic labelling ────────────────────────────────────────────────────
    # A row is labelled anomalous (1) when any of these thresholds are exceeded.
    # In a production setting these would be replaced with ground-truth labels.
    feature_df[label_column] = 0
    feature_df.loc[
        (feature_df["login_count"]              > 20) |
        (feature_df["failed_login_count"]       > 10) |
        (feature_df["unique_hosts"]             > 5)  |
        (feature_df["resource_access_count"]    > 30) |
        (feature_df["after_hours_logins"]       > 3)  |
        (feature_df["unusual_logon_type_count"] > 2)  |
        (feature_df["max_hosts_per_10min"]      > 3),
        label_column
    ] = 1

    normal_count   = (feature_df[label_column] == 0).sum()
    anomaly_count  = (feature_df[label_column] == 1).sum()
    logger.info(
        "Hybrid dataset: %d records (%d normal, %d anomaly)",
        len(feature_df), normal_count, anomaly_count,
    )
    return feature_df


# ──────────────────────────────────────────────────────────────────────────────
# Demo synthetic dataset generator (for testing without real data)
# ──────────────────────────────────────────────────────────────────────────────

def generate_synthetic_dataset(
    n_normal: int = 1000,
    n_anomaly: int = 100,
    random_seed: int = 42,
) -> pd.DataFrame:
    """Generate a synthetic dataset that mimics real UEBA feature distributions.

    Useful for unit-testing the pipeline when no real data is available.
    """
    rng = np.random.default_rng(random_seed)

    # Normal behaviour
    normal = pd.DataFrame({
        "login_count":              rng.integers(1, 8,  n_normal),
        "failed_login_count":       rng.integers(0, 2,  n_normal),
        "unique_hosts":             rng.integers(1, 3,  n_normal),
        "resource_access_count":    rng.integers(0, 10, n_normal),
        "after_hours_logins":       rng.integers(0, 1,  n_normal),
        "unusual_logon_type_count": rng.integers(0, 1,  n_normal),
        "type_2_ratio":             rng.uniform(0.7, 1.0, n_normal),
        "type_3_ratio":             rng.uniform(0.0, 0.3, n_normal),
        "type_10_ratio":            rng.uniform(0.0, 0.05, n_normal),
        "max_hosts_per_10min":      rng.integers(1, 2,  n_normal),
        "label":                    0,
    })

    # Anomalous behaviour
    anomaly = pd.DataFrame({
        "login_count":              rng.integers(15, 50,  n_anomaly),
        "failed_login_count":       rng.integers(5,  30,  n_anomaly),
        "unique_hosts":             rng.integers(5,  15,  n_anomaly),
        "resource_access_count":    rng.integers(30, 100, n_anomaly),
        "after_hours_logins":       rng.integers(3,  10,  n_anomaly),
        "unusual_logon_type_count": rng.integers(2,  8,   n_anomaly),
        "type_2_ratio":             rng.uniform(0.0, 0.5,  n_anomaly),
        "type_3_ratio":             rng.uniform(0.0, 0.5,  n_anomaly),
        "type_10_ratio":            rng.uniform(0.1, 0.9,  n_anomaly),
        "max_hosts_per_10min":      rng.integers(4,  15,  n_anomaly),
        "label":                    1,
    })

    df = pd.concat([normal, anomaly], ignore_index=True).sample(
        frac=1, random_state=random_seed
    )
    logger.info(
        "Generated synthetic dataset: %d normal + %d anomaly = %d total",
        n_normal, n_anomaly, len(df),
    )
    return df
