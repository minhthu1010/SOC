"""
Tests for the SOC AI pipeline components.

Tests cover:
  - feature_extractor: parse_wazuh_alert, build_feature_vectors
  - dataset_builder:   generate_synthetic_dataset, build_hybrid_dataset
  - anomaly_detector:  UEBADetector train / predict / save / load / evaluate
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

# Adjust sys.path so we can import the ai_module package directly.
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from ai_module.feature_extractor import (
    FEATURE_COLUMNS,
    build_feature_vectors,
    parse_wazuh_alert,
    load_events_from_file,
)
from ai_module.dataset_builder import (
    build_hybrid_dataset,
    generate_synthetic_dataset,
    load_cert_dataset,
)
from ai_module.anomaly_detector import UEBADetector


# ──────────────────────────────────────────────────────────────────────────────
# Helper fixtures
# ──────────────────────────────────────────────────────────────────────────────

# Use a fixed reference time so tests are deterministic regardless of when they
# are run.  We pick a weekday (Monday) at 09:00 UTC that will always be in the
# past relative to any realistic run date.
_BASE_TS = datetime(2024, 1, 15, 9, 0, 0, tzinfo=timezone.utc)  # Monday 09:00


def _ts(offset_minutes: int = 0, hour: int | None = None) -> str:
    """Return an ISO-8601 UTC string relative to _BASE_TS."""
    ts = _BASE_TS + timedelta(minutes=offset_minutes)
    if hour is not None:
        ts = ts.replace(hour=hour, minute=0, second=0)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _make_wazuh_event(
    event_id: str = "4624",
    username: str = "testuser",
    logon_type: str = "2",
    workstation: str = "PC01",
    ts: str | None = None,
) -> dict:
    """Build a minimal Wazuh JSON alert dict."""
    return {
        "timestamp": ts or _ts(),
        "rule": {"id": "60106", "level": 3, "description": "Windows logon"},
        "data": {
            "win": {
                "system": {"eventID": event_id},
                "eventdata": {
                    "targetUserName": username,
                    "logonType": logon_type,
                    "workstationName": workstation,
                    "ipAddress": "192.168.1.10",
                    "shareName": "",
                },
            }
        },
    }


def _make_events(n: int = 20, username: str = "alice", logon_type: str = "2") -> list:
    return [
        _make_wazuh_event(
            username=username,
            logon_type=logon_type,
            workstation=f"PC{i % 5 + 1:02d}",
            ts=_ts(offset_minutes=i),
        )
        for i in range(n)
    ]


# ──────────────────────────────────────────────────────────────────────────────
# feature_extractor tests
# ──────────────────────────────────────────────────────────────────────────────

class TestParseWazuhAlert:
    def test_valid_4624_event(self):
        raw = _make_wazuh_event(event_id="4624", username="alice")
        result = parse_wazuh_alert(raw)
        assert result is not None
        assert result["username"] == "ALICE"
        assert result["event_id"] == "4624"
        assert result["success"] is True

    def test_valid_5140_event(self):
        raw = _make_wazuh_event(event_id="5140")
        result = parse_wazuh_alert(raw)
        assert result is not None
        assert result["event_id"] == "5140"

    def test_irrelevant_event_id_returns_none(self):
        raw = _make_wazuh_event(event_id="4688")  # process creation – not relevant
        assert parse_wazuh_alert(raw) is None

    def test_invalid_json_string_returns_none(self):
        assert parse_wazuh_alert("not valid json{{{") is None

    def test_json_string_input(self):
        raw = json.dumps(_make_wazuh_event())
        result = parse_wazuh_alert(raw)
        assert result is not None

    def test_logon_type_extracted(self):
        raw = _make_wazuh_event(logon_type="10")
        result = parse_wazuh_alert(raw)
        assert result["logon_type"] == "10"

    def test_workstation_uppercased(self):
        raw = _make_wazuh_event(workstation="laptop-dev")
        result = parse_wazuh_alert(raw)
        assert result["workstation"] == "LAPTOP-DEV"

    def test_failed_logon_4625(self):
        raw = _make_wazuh_event(event_id="4625")
        result = parse_wazuh_alert(raw)
        assert result is not None
        assert result["success"] is False


class TestBuildFeatureVectors:
    def test_basic_shape(self):
        events = [parse_wazuh_alert(_make_wazuh_event()) for _ in range(5)]
        df = build_feature_vectors([e for e in events if e])
        assert not df.empty
        for col in FEATURE_COLUMNS:
            assert col in df.columns

    def test_empty_events_returns_empty_df(self):
        df = build_feature_vectors([])
        assert df.empty

    def test_login_count_correct(self):
        events = [parse_wazuh_alert(_make_wazuh_event(ts=_ts(offset_minutes=i)))
                  for i in range(5)]
        df = build_feature_vectors([e for e in events if e])
        assert df["login_count"].sum() == 5

    def test_after_hours_login_detected(self):
        # 22:00 is outside business hours
        events = [parse_wazuh_alert(_make_wazuh_event(ts=_ts(hour=22)))]
        df = build_feature_vectors([e for e in events if e])
        assert df["after_hours_logins"].sum() >= 1

    def test_unusual_logon_type_10(self):
        events = [parse_wazuh_alert(_make_wazuh_event(logon_type="10"))]
        df = build_feature_vectors([e for e in events if e])
        assert df["unusual_logon_type_count"].sum() >= 1

    def test_unique_hosts_counted(self):
        raw_events = [
            parse_wazuh_alert(_make_wazuh_event(workstation=f"PC{i:02d}",
                                                 ts=_ts(offset_minutes=i)))
            for i in range(4)
        ]
        df = build_feature_vectors([e for e in raw_events if e])
        assert df["unique_hosts"].max() == 4

    def test_multiple_users_separate_rows(self):
        events_alice = _make_events(5, username="alice")
        events_bob   = _make_events(5, username="bob")
        all_events = [parse_wazuh_alert(e) for e in events_alice + events_bob]
        df = build_feature_vectors([e for e in all_events if e])
        assert df["username"].nunique() == 2

    def test_failed_login_count(self):
        events = [
            parse_wazuh_alert(_make_wazuh_event(event_id="4625", ts=_ts(offset_minutes=i)))
            for i in range(3)
        ]
        df = build_feature_vectors([e for e in events if e])
        assert df["failed_login_count"].sum() == 3


class TestLoadEventsFromFile:
    def test_load_from_jsonl(self, tmp_path):
        fpath = tmp_path / "alerts.jsonl"
        events = [_make_wazuh_event(ts=_ts(offset_minutes=i)) for i in range(3)]
        with fpath.open("w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        loaded = load_events_from_file(fpath)
        assert len(loaded) == 3

    def test_nonexistent_file_returns_empty(self, tmp_path):
        loaded = load_events_from_file(tmp_path / "missing.jsonl")
        assert loaded == []

    def test_blank_lines_skipped(self, tmp_path):
        fpath = tmp_path / "alerts.jsonl"
        with fpath.open("w") as fh:
            fh.write("\n")
            fh.write(json.dumps(_make_wazuh_event()) + "\n")
            fh.write("  \n")
        loaded = load_events_from_file(fpath)
        assert len(loaded) == 1


# ──────────────────────────────────────────────────────────────────────────────
# dataset_builder tests
# ──────────────────────────────────────────────────────────────────────────────

class TestGenerateSyntheticDataset:
    def test_shape(self):
        df = generate_synthetic_dataset(n_normal=100, n_anomaly=10)
        assert len(df) == 110
        for col in FEATURE_COLUMNS:
            assert col in df.columns
        assert "label" in df.columns

    def test_label_distribution(self):
        df = generate_synthetic_dataset(n_normal=200, n_anomaly=20)
        assert df["label"].sum() == 20
        assert (df["label"] == 0).sum() == 200

    def test_reproducible_with_seed(self):
        df1 = generate_synthetic_dataset(random_seed=7)
        df2 = generate_synthetic_dataset(random_seed=7)
        pd.testing.assert_frame_equal(df1.reset_index(drop=True),
                                      df2.reset_index(drop=True))

    def test_anomaly_features_higher(self):
        df = generate_synthetic_dataset(n_normal=500, n_anomaly=50, random_seed=0)
        normal_mean  = df[df["label"] == 0]["login_count"].mean()
        anomaly_mean = df[df["label"] == 1]["login_count"].mean()
        assert anomaly_mean > normal_mean


class TestBuildHybridDataset:
    def test_empty_paths_returns_empty(self):
        df = build_hybrid_dataset()
        assert df.empty

    def test_with_lab_jsonl(self, tmp_path):
        fpath = tmp_path / "alerts.jsonl"
        events = [_make_wazuh_event(ts=_ts(offset_minutes=i)) for i in range(5)]
        with fpath.open("w") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        df = build_hybrid_dataset(lab_jsonl_path=fpath)
        assert not df.empty
        assert "label" in df.columns

    def test_label_column_present(self, tmp_path):
        fpath = tmp_path / "alerts.jsonl"
        with fpath.open("w") as fh:
            fh.write(json.dumps(_make_wazuh_event()) + "\n")
        df = build_hybrid_dataset(lab_jsonl_path=fpath)
        assert "label" in df.columns
        assert set(df["label"].unique()).issubset({0, 1})

    def test_cert_dataset_not_found_warns(self, tmp_path, caplog):
        import logging
        with caplog.at_level(logging.WARNING):
            df = build_hybrid_dataset(cert_csv_path=tmp_path / "missing.csv")
        assert df.empty


# ──────────────────────────────────────────────────────────────────────────────
# anomaly_detector tests
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def trained_detector():
    df = generate_synthetic_dataset(n_normal=300, n_anomaly=30, random_seed=0)
    detector = UEBADetector(contamination=0.1, n_estimators=50, random_state=0)
    detector.train(df, label_column="label")
    return detector


@pytest.fixture
def small_df():
    return generate_synthetic_dataset(n_normal=50, n_anomaly=5, random_seed=1)


class TestUEBADetectorTrain:
    def test_trains_without_error(self, small_df):
        detector = UEBADetector(n_estimators=10)
        detector.train(small_df)
        assert detector._model is not None
        assert detector._scaler is not None

    def test_semi_supervised_mode(self, small_df):
        detector = UEBADetector(n_estimators=10)
        detector.train(small_df, label_column="label")
        assert detector._model is not None

    def test_raises_before_training(self, small_df):
        detector = UEBADetector()
        with pytest.raises(RuntimeError, match="not trained"):
            detector.predict(small_df)

    def test_missing_feature_column_raises(self):
        detector = UEBADetector(n_estimators=10)
        df = generate_synthetic_dataset(n_normal=50, n_anomaly=5)
        df.drop(columns=["login_count"], inplace=True)
        with pytest.raises(ValueError, match="Missing feature columns"):
            detector.train(df)


class TestUEBADetectorPredict:
    def test_prediction_columns(self, trained_detector, small_df):
        result = trained_detector.predict(small_df)
        assert "ai_score" in result.columns
        assert "ai_prediction" in result.columns
        assert "ai_behaviours" in result.columns

    def test_predictions_are_binary(self, trained_detector, small_df):
        result = trained_detector.predict(small_df)
        assert set(result["ai_prediction"].unique()).issubset({0, 1})

    def test_anomalies_detected(self, trained_detector):
        # Use clearly anomalous data
        df = generate_synthetic_dataset(n_normal=0, n_anomaly=20, random_seed=5)
        result = trained_detector.predict(df)
        # At least some anomalies should be detected
        assert result["ai_prediction"].sum() > 0

    def test_normal_data_mostly_not_anomalous(self, trained_detector):
        df = generate_synthetic_dataset(n_normal=100, n_anomaly=0, random_seed=5)
        result = trained_detector.predict(df)
        fp_rate = result["ai_prediction"].mean()
        assert fp_rate < 0.25  # less than 25% false positive rate

    def test_ai_behaviours_is_list(self, trained_detector, small_df):
        result = trained_detector.predict(small_df)
        for behaviours in result["ai_behaviours"]:
            assert isinstance(behaviours, list)

    def test_ai_score_is_numeric(self, trained_detector, small_df):
        result = trained_detector.predict(small_df)
        assert result["ai_score"].dtype in (float, np.float32, np.float64)


class TestUEBADetectorEvaluate:
    def test_returns_expected_keys(self, trained_detector, small_df):
        metrics = trained_detector.evaluate(small_df)
        for key in ("roc_auc", "precision", "recall", "f1", "accuracy"):
            assert key in metrics

    def test_metrics_are_in_valid_range(self, trained_detector, small_df):
        metrics = trained_detector.evaluate(small_df)
        for key in ("precision", "recall", "f1", "accuracy"):
            assert 0.0 <= metrics[key] <= 1.0
        assert 0.0 <= metrics["roc_auc"] <= 1.0 or np.isnan(metrics["roc_auc"])

    def test_missing_label_column_raises(self, trained_detector, small_df):
        df = small_df.drop(columns=["label"])
        with pytest.raises(ValueError):
            trained_detector.evaluate(df, label_column="label")


class TestUEBADetectorPersistence:
    def test_save_and_load(self, trained_detector, small_df, tmp_path):
        model_file = tmp_path / "model.joblib"
        trained_detector.save(model_file)
        assert model_file.exists()

        loaded = UEBADetector.load(model_file)
        original_result = trained_detector.predict(small_df)
        loaded_result   = loaded.predict(small_df)
        pd.testing.assert_series_equal(
            original_result["ai_prediction"],
            loaded_result["ai_prediction"],
        )

    def test_load_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            UEBADetector.load(tmp_path / "nonexistent.joblib")

    def test_save_creates_parent_dirs(self, trained_detector, tmp_path):
        nested_path = tmp_path / "models" / "sub" / "model.joblib"
        trained_detector.save(nested_path)
        assert nested_path.exists()


class TestUEBADetectorAlertWazuh:
    def test_writes_alerts_to_log(self, trained_detector, tmp_path):
        import ai_module.anomaly_detector as mod
        original = mod.WAZUH_AI_ALERT_LOG
        alert_log = str(tmp_path / "ai_alerts.log")
        mod.WAZUH_AI_ALERT_LOG = alert_log

        try:
            df = generate_synthetic_dataset(n_normal=0, n_anomaly=5, random_seed=2)
            result = trained_detector.predict(df)
            # Force all to be predicted as anomaly for the test
            result["ai_prediction"] = 1
            result["username"] = "testuser"
            result["window"] = pd.Timestamp("2024-01-01", tz="UTC")
            written = trained_detector.alert_wazuh(result)
            assert written == len(result)
            # Verify file content
            lines = Path(alert_log).read_text().splitlines()
            assert len(lines) == len(result)
            for line in lines:
                alert = json.loads(line)
                assert "ai_alert" in alert
                assert "ai_score" in alert
                assert "user" in alert
        finally:
            mod.WAZUH_AI_ALERT_LOG = original

    def test_no_anomalies_writes_nothing(self, trained_detector, tmp_path):
        import ai_module.anomaly_detector as mod
        alert_log = str(tmp_path / "ai_alerts.log")
        original = mod.WAZUH_AI_ALERT_LOG
        mod.WAZUH_AI_ALERT_LOG = alert_log

        try:
            df = generate_synthetic_dataset(n_normal=5, n_anomaly=0, random_seed=3)
            result = trained_detector.predict(df)
            result["ai_prediction"] = 0  # force no anomalies
            written = trained_detector.alert_wazuh(result)
            assert written == 0
            assert not Path(alert_log).exists()
        finally:
            mod.WAZUH_AI_ALERT_LOG = original


# ──────────────────────────────────────────────────────────────────────────────
# Behaviour-specific detection tests (the 5 required behaviours)
# ──────────────────────────────────────────────────────────────────────────────

class TestBehaviourDetection:
    """End-to-end tests for each of the 5 required UEBA behaviours."""

    @pytest.fixture(autouse=True)
    def setup(self):
        train_df = generate_synthetic_dataset(n_normal=500, n_anomaly=50, random_seed=42)
        self.detector = UEBADetector(contamination=0.1, n_estimators=100, random_state=42)
        self.detector.train(train_df, label_column="label")

    def _predict_single(self, overrides: dict) -> dict:
        base = {col: 0 for col in FEATURE_COLUMNS}
        base.update(overrides)
        df = pd.DataFrame([base])
        result = self.detector.predict(df)
        return result.iloc[0].to_dict()

    def test_behaviour1_abnormal_login_frequency(self):
        row = self._predict_single({"login_count": 45, "unique_hosts": 1})
        assert row["ai_prediction"] == 1 or "high_login_frequency" in str(row["ai_behaviours"])

    def test_behaviour2_abnormal_resource_access(self):
        row = self._predict_single({"resource_access_count": 80})
        assert row["ai_prediction"] == 1 or "high_resource_access" in str(row["ai_behaviours"])

    def test_behaviour3_abnormal_logon_type(self):
        row = self._predict_single({
            "unusual_logon_type_count": 5,
            "type_10_ratio": 0.9,
            "type_2_ratio": 0.0,
        })
        assert row["ai_prediction"] == 1 or "unusual_logon_type" in str(row["ai_behaviours"])

    def test_behaviour4_after_hours_logins(self):
        row = self._predict_single({"after_hours_logins": 8, "login_count": 9})
        assert row["ai_prediction"] == 1 or "after_hours_activity" in str(row["ai_behaviours"])

    def test_behaviour5_host_spike(self):
        row = self._predict_single({
            "max_hosts_per_10min": 10,
            "unique_hosts": 12,
        })
        assert row["ai_prediction"] == 1 or "lateral_movement_spike" in str(row["ai_behaviours"])
