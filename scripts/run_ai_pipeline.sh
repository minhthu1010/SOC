#!/bin/bash
# =============================================================================
# run_ai_pipeline.sh – Continuously run the UEBA AI detection pipeline
#
# Watches the Wazuh alert stream, extracts features, scores with Isolation
# Forest, and injects anomaly alerts back into Wazuh.
#
# Usage:
#   ./run_ai_pipeline.sh [--train] [--cert-csv <path>] [--lab-jsonl <path>]
#
# Options:
#   --train         (Re)train the model before starting live detection.
#   --cert-csv      Path to CERT r4.2 CSV for training.
#   --lab-jsonl     Path to existing Wazuh JSONL export for training.
#   --synthetic     Use synthetic data if no real datasets are available.
#   --interval      Seconds between detection cycles (default: 300).
# =============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}/.."
AI_MODULE="${REPO_ROOT}/ai_module"

WAZUH_ALERTS_JSON="/var/ossec/logs/alerts/alerts.json"
MODEL_PATH="/opt/soc/models/ueba_model.joblib"
VENV_PATH="/opt/soc/venv"
TRAIN_MODE="false"
CERT_CSV=""
LAB_JSONL=""
SYNTHETIC="false"
INTERVAL=300

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --train)      TRAIN_MODE="true";;
        --cert-csv)   CERT_CSV="$2"; shift;;
        --lab-jsonl)  LAB_JSONL="$2"; shift;;
        --synthetic)  SYNTHETIC="true";;
        --interval)   INTERVAL="$2"; shift;;
        *) warn "Unknown argument: $1";;
    esac
    shift
done

# ── Ensure Python venv ────────────────────────────────────────────────────────
if [[ ! -d "${VENV_PATH}" ]]; then
    info "Creating Python virtual environment at ${VENV_PATH}..."
    python3 -m venv "${VENV_PATH}"
fi

# shellcheck disable=SC1091
source "${VENV_PATH}/bin/activate"

pip install -q --upgrade pip
pip install -q -r "${AI_MODULE}/requirements.txt"

# ── (Re)train model ───────────────────────────────────────────────────────────
if [[ "${TRAIN_MODE}" == "true" ]]; then
    info "Training UEBA model..."
    TRAIN_ARGS=""
    [[ -n "${CERT_CSV}"  ]] && TRAIN_ARGS+=" --cert-csv ${CERT_CSV}"
    [[ -n "${LAB_JSONL}" ]] && TRAIN_ARGS+=" --lab-jsonl ${LAB_JSONL}"
    [[ "${SYNTHETIC}" == "true" ]] && TRAIN_ARGS+=" --synthetic"

    # shellcheck disable=SC2086
    python3 -m ai_module.pipeline train \
        --model-path "${MODEL_PATH}" \
        ${TRAIN_ARGS}
    info "Training complete."
fi

# Make sure a model exists before entering detect loop
if [[ ! -f "${MODEL_PATH}" ]]; then
    warn "No trained model found at ${MODEL_PATH}. Training with synthetic data..."
    python3 -m ai_module.pipeline train \
        --model-path "${MODEL_PATH}" \
        --synthetic
fi

# ── Detection loop ────────────────────────────────────────────────────────────
info "Starting detection loop (interval: ${INTERVAL}s)..."
LIVE_JSONL="/tmp/wazuh_live_window.jsonl"

while true; do
    # Extract the last N lines of the Wazuh alert stream as the "live window"
    if [[ -f "${WAZUH_ALERTS_JSON}" ]]; then
        tail -n 5000 "${WAZUH_ALERTS_JSON}" > "${LIVE_JSONL}"
        python3 -m ai_module.pipeline detect "${LIVE_JSONL}" \
            --model-path "${MODEL_PATH}" \
            --output-csv "/tmp/ai_detection_$(date +%Y%m%d_%H%M%S).csv" \
            2>&1 | tail -20
    else
        warn "Wazuh alert stream not found: ${WAZUH_ALERTS_JSON}"
    fi

    info "Sleeping ${INTERVAL}s until next detection cycle..."
    sleep "${INTERVAL}"
done
