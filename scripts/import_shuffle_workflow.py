#!/usr/bin/env python3
"""
import_shuffle_workflow.py – Import SOC Triage Workflow into Shuffle
====================================================================
Uploads the soc_triage_workflow.json to Shuffle via its REST API.
Also creates the required webhook and prints the URL to paste into ossec.conf.

Usage:
    python3 import_shuffle_workflow.py \
        --shuffle-url http://localhost:5001 \
        --username admin \
        --password password \
        --workflow-file ../shuffle_workflows/soc_triage_workflow.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# NOTE: SSL verification is disabled by default because Shuffle uses a
# self-signed certificate in typical lab deployments.  In production, pass
# --verify-ssl and provide a trusted CA bundle via the REQUESTS_CA_BUNDLE
# environment variable.


def get_auth_token(base_url: str, username: str, password: str) -> str:
    resp = requests.post(
        f"{base_url}/api/v1/login",
        json={"username": username, "password": password},
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    token = resp.json().get("success")
    if not token:
        raise RuntimeError(f"Login failed: {resp.text}")
    # Shuffle returns a cookie/session – grab the session cookie
    return resp.cookies.get("session_token", "")


def import_workflow(
    base_url: str,
    session: requests.Session,
    workflow_path: Path,
) -> str:
    """Upload workflow JSON and return the workflow ID."""
    with workflow_path.open() as fh:
        wf_data = json.load(fh)

    resp = session.post(
        f"{base_url}/api/v1/workflows",
        json=wf_data,
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    wf_id = resp.json().get("id", wf_data.get("id"))
    print(f"[OK] Workflow imported with ID: {wf_id}")
    return wf_id


def activate_workflow(base_url: str, session: requests.Session, wf_id: str) -> None:
    resp = session.post(
        f"{base_url}/api/v1/workflows/{wf_id}/run",
        json={"start": True},
        verify=False,
        timeout=10,
    )
    # 200 or 202 both OK
    if resp.status_code not in (200, 202):
        print(f"[WARN] Workflow activation returned HTTP {resp.status_code}: {resp.text}")
    else:
        print("[OK] Workflow activated.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Import SOC triage workflow into Shuffle")
    parser.add_argument("--shuffle-url",   default="http://localhost:5001",
                        help="Shuffle backend URL (default: http://localhost:5001)")
    parser.add_argument("--username",      default="admin")
    parser.add_argument("--password",      default="password")
    parser.add_argument("--workflow-file",
                        default=str(Path(__file__).parent.parent /
                                    "shuffle_workflows" / "soc_triage_workflow.json"))
    parser.add_argument("--verify-ssl",    action="store_true",
                        help="Enable SSL certificate verification (recommended for production)")
    args = parser.parse_args()

    wf_path = Path(args.workflow_file)
    if not wf_path.exists():
        print(f"[ERROR] Workflow file not found: {wf_path}", file=sys.stderr)
        sys.exit(1)

    session = requests.Session()
    print(f"[INFO] Connecting to Shuffle: {args.shuffle_url}")

    try:
        resp = session.post(
            f"{args.shuffle_url}/api/v1/login",
            json={"username": args.username, "password": args.password},
            verify=False,
            timeout=10,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"[ERROR] Cannot connect to Shuffle: {exc}", file=sys.stderr)
        sys.exit(1)

    wf_id = import_workflow(args.shuffle_url, session, wf_path)
    activate_workflow(args.shuffle_url, session, wf_id)

    webhook_url = (
        f"{args.shuffle_url}/api/v1/hooks/webhook_soc_triage"
    )
    print("\n══════════════════════════════════════════════════════════════")
    print(" Wazuh ← → Shuffle integration webhook URL:")
    print(f"   {webhook_url}")
    print(" Add this to /var/ossec/etc/ossec.conf:")
    print("   <integration>")
    print("     <name>shuffle</name>")
    print(f"     <hook_url>{webhook_url}</hook_url>")
    print("     <level>7</level>")
    print("     <alert_format>json</alert_format>")
    print("   </integration>")
    print("══════════════════════════════════════════════════════════════\n")


if __name__ == "__main__":
    main()
