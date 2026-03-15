# SOC – Intelligent Security Incident Monitoring & Automated Response

> Wazuh SIEM · Shuffle SOAR · Isolation Forest AI · Ubuntu Lab

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Directory Layout](#directory-layout)
4. [Prerequisites](#prerequisites)
5. [Quick Start](#quick-start)
6. [Detected Behaviours](#detected-behaviours)
7. [Hybrid Dataset](#hybrid-dataset)
8. [AI Module Reference](#ai-module-reference)
9. [Wazuh Rules Reference](#wazuh-rules-reference)
10. [Shuffle Workflow Reference](#shuffle-workflow-reference)
11. [Testing](#testing)
12. [Lab Environment](#lab-environment)

---

## Overview

This repository implements a **complete SOC pipeline** that:

| Layer | Technology | Role |
|-------|-----------|------|
| Log collection | **Wazuh 4.7 Agent** (Windows) | Collects Security/Sysmon Event Channel logs |
| SIEM / correlation | **Wazuh Manager + Indexer** (Ubuntu) | Parses, indexes, and fires rule-based alerts |
| AI detection | **Isolation Forest** (Python / scikit-learn) | Detects UEBA anomalies from feature vectors |
| SOAR | **Shuffle 1.4** (Docker, Ubuntu) | Receives alerts, orchestrates automated response |
| Response | Active Response / TheHive / Slack | Isolates hosts, disables accounts, creates cases |

The AI model is trained on a **Hybrid Dataset** that combines:
- [CERT Insider Threat Dataset r4.2](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099) (simulated user activity CSV)
- **Lab Dataset** – real Wazuh JSONL alerts exported from the lab environment

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Windows Endpoints (real machine + Windows 10 VM)                   │
│  ┌───────────────────────────────────┐                              │
│  │  Wazuh Agent   <─ Event Channel  │                              │
│  │  (Event 4624/4625/5140/5145 …)   │                              │
│  └──────────────────┬────────────────┘                              │
└─────────────────────┼───────────────────────────────────────────────┘
                      │ TCP 1514 (encrypted)
┌─────────────────────▼───────────────────────────────────────────────┐
│  Ubuntu Server                                                      │
│                                                                     │
│  ┌──────────────┐    alerts.json    ┌─────────────────────────┐    │
│  │ Wazuh Manager│ ─────────────────>│  AI Pipeline (Python)   │    │
│  │ + Indexer    │                   │  feature_extractor      │    │
│  │ + Dashboard  │<── inject alert ──│  anomaly_detector       │    │
│  └──────┬───────┘  ai_alerts.log    │  (Isolation Forest)     │    │
│         │                           └─────────────────────────┘    │
│         │  Webhook (HTTP POST)                                      │
│         ▼                                                           │
│  ┌──────────────┐                                                   │
│  │  Shuffle SOAR│                                                   │
│  │  Workflow:   │                                                   │
│  │  • parse     │                                                   │
│  │  • route     │                                                   │
│  │  • isolate   │──> Wazuh Active Response (disable-account /      │
│  │  • case      │    firewall-drop)                                 │
│  │  • notify    │──> TheHive case / Slack alert / email            │
│  └──────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Directory Layout

```
SOC/
├── scripts/
│   ├── install_wazuh.sh              # Install Wazuh Manager on Ubuntu
│   ├── install_shuffle.sh            # Install Shuffle SOAR via Docker
│   ├── deploy_wazuh_agent_windows.sh # Generate Windows agent installer
│   ├── run_ai_pipeline.sh            # Continuous AI detection loop
│   └── import_shuffle_workflow.py    # Upload workflow to Shuffle API
│
├── ai_module/
│   ├── __init__.py
│   ├── feature_extractor.py          # Parse Wazuh events → feature vectors
│   ├── dataset_builder.py            # Hybrid Dataset (CERT + Lab)
│   ├── anomaly_detector.py           # Isolation Forest UEBA detector
│   ├── pipeline.py                   # CLI: train / detect / evaluate
│   └── requirements.txt
│
├── wazuh_config/
│   ├── ossec.conf                    # Wazuh Manager main config
│   ├── soc_custom_rules.xml          # Custom detection rules (5 behaviours)
│   └── custom_decoders.xml           # Decoder for AI alert JSON
│
├── shuffle_workflows/
│   └── soc_triage_workflow.json      # Shuffle automation workflow
│
├── agent_config/                     # Generated Windows agent scripts
│
├── datasets/                         # Place CERT r4.2 CSV here
│
└── tests/
    └── test_ai_pipeline.py           # 50 pytest tests
```

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Ubuntu | 20.04 / 22.04 LTS | For Wazuh + Shuffle |
| RAM | >= 8 GB | Wazuh Indexer + Shuffle need at least 6 GB |
| Disk | >= 50 GB | Wazuh indices grow over time |
| Docker Engine | >= 24 | For Shuffle (installed by install_shuffle.sh) |
| Python | >= 3.9 | For the AI module |
| Windows | 10 / 11 | Endpoint to monitor |

---

## Quick Start

### Step 1 – Install Wazuh on Ubuntu

```bash
sudo bash scripts/install_wazuh.sh
```

This script installs and configures Wazuh Indexer (OpenSearch), Wazuh Manager, and Wazuh Dashboard, then deploys the custom SOC rules.

After installation, access the dashboard at `https://<ubuntu-ip>:443` with `admin / WazuhAdmin@SOC2024`.

### Step 2 – Install Shuffle on Ubuntu

```bash
sudo bash scripts/install_shuffle.sh
```

Access Shuffle at `http://<ubuntu-ip>:3001` (default credentials: `admin / password`).

### Step 3 – Deploy Wazuh Agent on Windows

```bash
# On Ubuntu manager (as root)
sudo bash scripts/deploy_wazuh_agent_windows.sh <ubuntu-ip>
```

Copy the generated `agent_config/Install-WazuhAgent.ps1` to each Windows machine and run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Install-WazuhAgent.ps1
```

### Step 4 – Import Shuffle Workflow

```bash
pip3 install requests
python3 scripts/import_shuffle_workflow.py \
    --shuffle-url http://localhost:5001 \
    --username admin \
    --password password
```

### Step 5 – Train the AI Model

```bash
# Export Wazuh alerts first
sudo cat /var/ossec/logs/alerts/alerts.json > /tmp/lab_alerts.jsonl

python3 -m ai_module.pipeline train \
    --lab-jsonl /tmp/lab_alerts.jsonl \
    --cert-csv  datasets/r4.2-1.csv \
    --model-path /opt/soc/models/ueba_model.joblib

# Or use synthetic data for testing:
python3 -m ai_module.pipeline train --synthetic
```

### Step 6 – Run the Live Detection Loop

```bash
sudo bash scripts/run_ai_pipeline.sh
```

The script runs the AI detection every 5 minutes, writing anomaly alerts to `/var/ossec/logs/ai_alerts.log` where Wazuh picks them up and forwards to Shuffle.

---

## Detected Behaviours

| # | Behaviour | Wazuh Rule | AI Feature |
|---|-----------|-----------|------------|
| 1 | Abnormal login frequency (>=10 logins in 2 min) | 100010 | `login_count` |
| 2 | Abnormal resource access (>=15 shares in 5 min) | 100020–100021 | `resource_access_count` |
| 3 | Abnormal logon type (Type 8/9/10) | 100030–100033 | `unusual_logon_type_count`, `type_10_ratio` |
| 4 | Login outside business hours (20:00–06:00) | 100040 | `after_hours_logins` |
| 5 | Host access spike (>=5 hosts in 10 min) | 100050 | `max_hosts_per_10min`, `unique_hosts` |

---

## Hybrid Dataset

The dataset builder (`ai_module/dataset_builder.py`) merges two sources:

### CERT r4.2
Download from [CMU SEI](https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099).
Place CSV files (e.g. `r4.2-1.csv`) in the `datasets/` directory.

### Lab Dataset
```bash
sudo cat /var/ossec/logs/alerts/alerts.json > datasets/lab_alerts.jsonl
```

### Combined training
```bash
python3 -m ai_module.pipeline train \
    --cert-csv  datasets/r4.2-1.csv \
    --lab-jsonl datasets/lab_alerts.jsonl
```

---

## AI Module Reference

### `train`
```
python3 -m ai_module.pipeline train [OPTIONS]

  --cert-csv PATH        CERT r4.2 CSV
  --lab-jsonl PATH       Wazuh JSONL export
  --synthetic            Use synthetic data
  --n-normal INT         Normal samples (default 1000)
  --n-anomaly INT        Anomaly samples (default 100)
  --contamination FLOAT  Expected anomaly fraction (default 0.05)
  --n-estimators INT     Number of trees (default 200)
  --window INT           Aggregation window minutes (default 60)
  --model-path PATH      Save path
```

### `detect`
```
python3 -m ai_module.pipeline detect JSONL_FILE [OPTIONS]

  --model-path PATH
  --window INT
  --output-csv PATH   Save results to CSV
```

### `evaluate`
```
python3 -m ai_module.pipeline evaluate [OPTIONS]

  --cert-csv PATH
  --lab-jsonl PATH
  --model-path PATH
  --window INT
```

---

## Wazuh Rules Reference

| Rule ID | Level | Description |
|---------|-------|-------------|
| 100010 | 10 | Abnormal login frequency (>=10 in 2 min) |
| 100020 | 8  | Abnormal network share access (>=15 in 5 min) |
| 100021 | 9  | Abnormal detailed file share access (>=20 in 5 min) |
| 100030 | 10 | RDP (logon type 10) detected |
| 100031 | 12 | NetworkCleartext logon (type 8) |
| 100032 | 10 | NewCredentials logon (type 9 / RunAs) |
| 100033 | 8  | Service logon (type 5) for non-system account |
| 100040 | 9  | Login outside business hours (20:00–06:00) |
| 100050 | 12 | Lateral movement – >=5 different hosts in 10 min |
| 100061 | 13 | AI Isolation Forest anomaly detected |

---

## Shuffle Workflow Reference

`shuffle_workflows/soc_triage_workflow.json` implements:

```
Wazuh Webhook
    -> parse_alert
    -> route_by_severity
         -> Level >= 12: isolate host + disable account (Wazuh Active Response)
         -> Level >= 9:  email SOC team
         -> Level >= 7:  write ticket
    -> create_case (TheHive)
    -> notify (Slack)
```

---

## Testing

```bash
pip install -r ai_module/requirements.txt pytest
python -m pytest tests/test_ai_pipeline.py -v
```

50 tests covering feature extraction, dataset building, model training, prediction, persistence, alert injection, and all 5 detected behaviours.

---

## Lab Environment

| Machine | OS | Role |
|---------|-----|------|
| Physical PC | Ubuntu 22.04 | Wazuh Manager + AI pipeline + Shuffle |
| Ubuntu VM | Ubuntu 22.04 | Additional log source |
| Windows 10 VM | Windows 10 | Monitored endpoint |
| Windows (real) | Windows 10/11 | Monitored endpoint |

Key ports:

| Port | Purpose |
|------|---------|
| 1514 TCP | Wazuh agent communication |
| 1515 TCP | Wazuh agent registration |
| 443 HTTPS | Wazuh Dashboard |
| 55000 HTTPS | Wazuh REST API |
| 3001 HTTP | Shuffle UI |
| 5001 HTTP | Shuffle backend / webhooks |
