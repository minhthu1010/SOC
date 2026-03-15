"""
pipeline.py – End-to-end SOC AI Pipeline
=========================================
Orchestrates:
  1. Event loading (lab JSONL + optional CERT r4.2 CSV)
  2. Feature extraction
  3. Model training or loading a saved model
  4. Live prediction
  5. Wazuh alert injection
  6. Reporting
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

import pandas as pd

from .anomaly_detector import UEBADetector
from .dataset_builder import build_hybrid_dataset, generate_synthetic_dataset
from .feature_extractor import load_events_from_file, build_feature_vectors, FEATURE_COLUMNS

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("soc.pipeline")

DEFAULT_MODEL_PATH  = "/opt/soc/models/ueba_model.joblib"
DEFAULT_WINDOW_MIN  = 60
DEFAULT_CONTAMINATION = 0.05


# ──────────────────────────────────────────────────────────────────────────────
def train(args: argparse.Namespace) -> None:
    """Train a new UEBA model and save it."""
    logger.info("═══ Training mode ═══")
    if args.synthetic:
        logger.info("Using synthetic dataset (no real data provided).")
        df = generate_synthetic_dataset(
            n_normal=args.n_normal,
            n_anomaly=args.n_anomaly,
        )
    else:
        df = build_hybrid_dataset(
            cert_csv_path=args.cert_csv,
            lab_jsonl_path=args.lab_jsonl,
            window_minutes=args.window,
        )

    if df.empty:
        logger.error("Empty dataset – cannot train. "
                     "Provide --cert-csv, --lab-jsonl, or use --synthetic.")
        sys.exit(1)

    detector = UEBADetector(
        contamination=args.contamination,
        n_estimators=args.n_estimators,
    )
    detector.train(df, label_column="label")

    if "label" in df.columns:
        metrics = detector.evaluate(df)
        logger.info("Training-set metrics: %s", metrics)

    model_path = args.model_path or DEFAULT_MODEL_PATH
    detector.save(model_path)
    logger.info("Model saved to %s", model_path)


# ──────────────────────────────────────────────────────────────────────────────
def detect(args: argparse.Namespace) -> None:
    """Load a saved model and run detection on a live JSONL file."""
    logger.info("═══ Detection mode ═══")

    model_path = args.model_path or DEFAULT_MODEL_PATH
    if not Path(model_path).exists():
        logger.error("Model not found: %s  – run 'train' first.", model_path)
        sys.exit(1)

    detector = UEBADetector.load(model_path)

    events = load_events_from_file(args.lab_jsonl)
    if not events:
        logger.warning("No events found in %s", args.lab_jsonl)
        return

    df = build_feature_vectors(events, window_minutes=args.window)
    if df.empty:
        logger.warning("Feature extraction produced no rows.")
        return

    results = detector.predict(df)
    n_anomalies = results["ai_prediction"].sum()
    logger.info("Detected %d anomaly window(s) out of %d.", n_anomalies, len(results))

    anomalies = results[results["ai_prediction"] == 1]
    if not anomalies.empty:
        logger.info("Anomalous users:\n%s",
                    anomalies[["username", "window", "ai_score", "ai_behaviours"]]
                    .to_string(index=False))
        written = detector.alert_wazuh(results)
        logger.info("Injected %d alert(s) into Wazuh.", written)

    if args.output_csv:
        results.to_csv(args.output_csv, index=False)
        logger.info("Results written to %s", args.output_csv)


# ──────────────────────────────────────────────────────────────────────────────
def evaluate(args: argparse.Namespace) -> None:
    """Evaluate a saved model against a labelled dataset."""
    logger.info("═══ Evaluation mode ═══")
    model_path = args.model_path or DEFAULT_MODEL_PATH
    detector   = UEBADetector.load(model_path)

    df = build_hybrid_dataset(
        cert_csv_path=args.cert_csv,
        lab_jsonl_path=args.lab_jsonl,
        window_minutes=args.window,
    )
    if df.empty:
        logger.error("Empty evaluation dataset.")
        sys.exit(1)

    metrics = detector.evaluate(df)
    print("\n── Evaluation Results ────────────────────────────────")
    for k, v in metrics.items():
        print(f"  {k:12s}: {v}")
    print("──────────────────────────────────────────────────────\n")


# ──────────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC UEBA Pipeline – Isolation Forest anomaly detection",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ── train ──────────────────────────────────────────────────────────────────
    p_train = sub.add_parser("train", help="Train or retrain the UEBA model.")
    p_train.add_argument("--cert-csv",       help="Path to CERT r4.2 CSV file.")
    p_train.add_argument("--lab-jsonl",      help="Path to Wazuh JSONL alert export.")
    p_train.add_argument("--synthetic",      action="store_true",
                         help="Use synthetic dataset instead of real data.")
    p_train.add_argument("--n-normal",       type=int, default=1000)
    p_train.add_argument("--n-anomaly",      type=int, default=100)
    p_train.add_argument("--contamination",  type=float, default=DEFAULT_CONTAMINATION)
    p_train.add_argument("--n-estimators",   type=int, default=200)
    p_train.add_argument("--window",         type=int, default=DEFAULT_WINDOW_MIN,
                         help="Aggregation window in minutes (default: 60).")
    p_train.add_argument("--model-path",     default=DEFAULT_MODEL_PATH)

    # ── detect ─────────────────────────────────────────────────────────────────
    p_detect = sub.add_parser("detect", help="Run live detection on a JSONL file.")
    p_detect.add_argument("lab_jsonl",      help="Path to Wazuh JSONL alerts.")
    p_detect.add_argument("--model-path",   default=DEFAULT_MODEL_PATH)
    p_detect.add_argument("--window",       type=int, default=DEFAULT_WINDOW_MIN)
    p_detect.add_argument("--output-csv",   help="Save results to CSV.")

    # ── evaluate ───────────────────────────────────────────────────────────────
    p_eval = sub.add_parser("evaluate", help="Evaluate model performance.")
    p_eval.add_argument("--cert-csv",    help="CERT r4.2 CSV.")
    p_eval.add_argument("--lab-jsonl",   help="Wazuh JSONL.")
    p_eval.add_argument("--model-path",  default=DEFAULT_MODEL_PATH)
    p_eval.add_argument("--window",      type=int, default=DEFAULT_WINDOW_MIN)

    args = parser.parse_args()

    dispatch = {"train": train, "detect": detect, "evaluate": evaluate}
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
