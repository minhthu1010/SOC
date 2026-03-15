"""
feature_extractor.py – Windows Event Log Feature Extraction for UEBA
=====================================================================
Reads raw Windows Security Event logs (JSON format as forwarded by Wazuh)
and computes per-user, per-hour feature vectors used by the Isolation Forest
anomaly detection model.

Detected behaviours:
  1. Abnormal login frequency
  2. Abnormal resource access
  3. Abnormal logon-type distribution  (Event 4624 logonType)
  4. Login outside business hours
  5. Spike in number of hosts accessed (lateral movement)
"""

from __future__ import annotations

import json
import logging
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ── Business-hours definition ──────────────────────────────────────────────────
# NOTE: These defaults suit a typical Mon–Fri 08:00–18:00 work schedule.
# Adjust WORK_HOUR_START, WORK_HOUR_END, and WORK_DAYS per your organisation's
# policy before deploying.  All times are evaluated in the timezone of the
# Wazuh manager host.
WORK_HOUR_START = 8   # 08:00
WORK_HOUR_END   = 18  # 18:00
WORK_DAYS       = {0, 1, 2, 3, 4}  # Mon–Fri (weekday() values)

# ── Windows logon types ────────────────────────────────────────────────────────
LOGON_TYPES = {
    "2": "interactive",
    "3": "network",
    "4": "batch",
    "5": "service",
    "7": "unlock",
    "8": "network_cleartext",
    "9": "new_credentials",
    "10": "remote_interactive",
    "11": "cached_interactive",
}
UNUSUAL_LOGON_TYPES = {"8", "9", "10"}


# ──────────────────────────────────────────────────────────────────────────────
def parse_wazuh_alert(raw: str | dict) -> dict[str, Any] | None:
    """Parse a single Wazuh JSON alert line.

    Returns a flat dict with the fields we care about, or *None* if the event
    is not a Windows authentication / resource-access event.
    """
    try:
        record = raw if isinstance(raw, dict) else json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None

    rule_id = str(record.get("rule", {}).get("id", ""))
    # Event IDs we care about: 4624, 4625, 4634, 5140, 5145
    win = record.get("data", {}).get("win", {})
    event_data = win.get("eventdata", {})
    system      = win.get("system", {})

    event_id    = str(system.get("eventID", ""))
    if event_id not in {"4624", "4625", "4634", "5140", "5145"}:
        return None

    try:
        ts = datetime.fromisoformat(record.get("timestamp", "").replace("Z", "+00:00"))
    except ValueError:
        ts = datetime.utcnow()

    username    = (event_data.get("targetUserName") or
                   event_data.get("subjectUserName") or "UNKNOWN").upper()
    logon_type  = str(event_data.get("logonType", "0"))
    workstation = (event_data.get("workstationName") or
                   event_data.get("ipWorkstationName") or "UNKNOWN").upper()
    ip_address  = event_data.get("ipAddress", "")
    share_name  = event_data.get("shareName", "")

    return {
        "timestamp":   ts,
        "username":    username,
        "event_id":    event_id,
        "logon_type":  logon_type,
        "workstation": workstation,
        "ip_address":  ip_address,
        "share_name":  share_name,
        "success":     event_id in {"4624", "5140", "5145"},
    }


# ──────────────────────────────────────────────────────────────────────────────
def build_feature_vectors(
    events: list[dict[str, Any]],
    window_minutes: int = 60,
) -> pd.DataFrame:
    """Aggregate raw events into per-user, per-window feature vectors.

    Parameters
    ----------
    events:
        List of dicts returned by :func:`parse_wazuh_alert`.
    window_minutes:
        Size of the rolling aggregation window (default: 60 min).

    Returns
    -------
    pd.DataFrame
        One row per (user, time-window) with columns:
        login_count, failed_login_count, unique_hosts, resource_access_count,
        after_hours_logins, unusual_logon_type_count, type_2_ratio,
        type_3_ratio, type_10_ratio, max_hosts_per_short_window.
    """
    if not events:
        return pd.DataFrame()

    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("timestamp")
    df["window"] = df["timestamp"].dt.floor(f"{window_minutes}min")

    rows = []
    for (username, window), grp in df.groupby(["username", "window"]):
        logins      = grp[grp["event_id"] == "4624"]
        failures    = grp[grp["event_id"] == "4625"]
        resource_ev = grp[grp["event_id"].isin({"5140", "5145"})]

        login_count          = len(logins)
        failed_login_count   = len(failures)
        unique_hosts         = logins["workstation"].nunique()
        resource_access_cnt  = len(resource_ev)

        # After-hours logins
        def _after_hours(ts: pd.Timestamp) -> bool:
            return (ts.hour < WORK_HOUR_START or ts.hour >= WORK_HOUR_END or
                    ts.weekday() not in WORK_DAYS)
        if len(logins) > 0:
            after_hours_logins = int(logins["timestamp"].apply(_after_hours).sum())
        else:
            after_hours_logins = 0

        # Logon-type features
        lt_counts = logins["logon_type"].value_counts()
        total     = max(login_count, 1)
        unusual_logon_type_count = lt_counts[
            lt_counts.index.isin(UNUSUAL_LOGON_TYPES)
        ].sum()
        type_2_ratio  = lt_counts.get("2",  0) / total
        type_3_ratio  = lt_counts.get("3",  0) / total
        type_10_ratio = lt_counts.get("10", 0) / total

        # Lateral-movement indicator: max hosts in any 10-min sub-window
        if len(logins) > 0:
            logins = logins.set_index("timestamp")
            max_hosts_short = (
                logins["workstation"]
                .resample("10min")
                .nunique()
                .max()
            )
        else:
            max_hosts_short = 0

        rows.append({
            "username":                username,
            "window":                  window,
            "login_count":             login_count,
            "failed_login_count":      failed_login_count,
            "unique_hosts":            unique_hosts,
            "resource_access_count":   resource_access_cnt,
            "after_hours_logins":      int(after_hours_logins),
            "unusual_logon_type_count": int(unusual_logon_type_count),
            "type_2_ratio":            round(type_2_ratio,  4),
            "type_3_ratio":            round(type_3_ratio,  4),
            "type_10_ratio":           round(type_10_ratio, 4),
            "max_hosts_per_10min":     int(max_hosts_short),
        })

    return pd.DataFrame(rows)


FEATURE_COLUMNS = [
    "login_count",
    "failed_login_count",
    "unique_hosts",
    "resource_access_count",
    "after_hours_logins",
    "unusual_logon_type_count",
    "type_2_ratio",
    "type_3_ratio",
    "type_10_ratio",
    "max_hosts_per_10min",
]


# ──────────────────────────────────────────────────────────────────────────────
def load_events_from_file(path: str | Path) -> list[dict[str, Any]]:
    """Read a JSONL file of Wazuh alerts and parse each line."""
    path = Path(path)
    events = []
    if not path.exists():
        logger.warning("Event file not found: %s", path)
        return events
    with path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            ev = parse_wazuh_alert(line)
            if ev:
                events.append(ev)
    logger.info("Loaded %d relevant events from %s", len(events), path)
    return events
