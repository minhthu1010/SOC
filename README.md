# SOC

Security Operations Center (SOC) demo repository for testing and learning purposes.

## Overview

This repository contains demo files used for SOC tooling, including:

- **Indicator of Compromise (IOC) testing** – sample files to validate detection rules
- **File Integrity Monitoring (FIM) testing** – files used to trigger and verify FIM alerts

## Files

| File | Description |
|------|-------------|
| `malware.txt` | Demo malware indicator file used for IOC testing |
| `demo-malware.txt` | Sample file used to trigger File Integrity Monitoring (FIM) |
| `malware-demo.exe` | Demo executable used for endpoint detection testing |

## Usage

These files are intended for use in a controlled SOC lab environment to:

1. Validate that your SIEM/EDR correctly detects known-bad indicators
2. Test FIM alerting by modifying the `demo-malware.txt` file
3. Practice incident response workflows in a safe, isolated setting

> **Warning:** Do not run or deploy these files outside of a controlled test environment.