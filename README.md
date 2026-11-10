# AI-Powered SOC Lab

A hands-on SOC engineering lab to build reproducible detection, normalization and triage workflows using both synthetic and real Windows telemetry.

## Current working scope (November 2026)

- Python detection and UTF-16LE/Base64 decoding of PowerShell `-EncodedCommand`, `-e`, `-ec`; decoded payloads are **not executed**.
- Versioned SOC `AlertEnvelope`/`Evidence` models with timestamp normalization and explicit `missing_evidence`.
- Read-only Splunk REST connector with bounded Sysmon searches, real-event alert construction and local triage.
- Correlation against Sysmon parent `ProcessGuid` and PowerShell Event 4104 script-block fragments. Missing parent/script evidence is reported instead of inferred.
- Offline Python tests; GitHub Actions executes them on pushes and pull requests to `main` and supports manual runs.

**Not built yet:** FastAPI REST/WebSocket service, persistent alerts, agentic AI/RAG investigation, dashboard, and automatic response/remediation.

## Architecture

WIN-LAB (Windows 11, Sysmon, PowerShell 4104) → Splunk Universal Forwarder → Splunk on Ubuntu/Proxmox → bounded REST API searches → Python SOC normalization, correlation and triage.

## Quick start: offline demonstration

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe .\triage.py --json
.\.venv\Scripts\python.exe -m pytest -v
```

Use test fixtures for CI; do not require live credentials or a Splunk server for automated unit tests.

## Live lab (private network only)

Requires a running Splunk instance and indexed Windows Sysmon/PowerShell events.

```powershell
python .\splunk_connector.py --host YOUR_SPLUNK_HOST --insecure-lab
python .\splunk_triage.py --host YOUR_SPLUNK_HOST --insecure-lab
python .\soc_correlation.py --host YOUR_SPLUNK_HOST --insecure-lab
```

`--insecure-lab` turns off TLS certificate verification. Use only temporarily on a trusted local lab. Prefer `--ca-file` for a trusted CA. Scripts prompt for credentials at runtime. Use a dedicated read-only account in future; `admin` is not recommended for ongoing integration.

## Test and CI

```powershell
python -m pytest -v --cov=triage --cov=detection_rules --cov=soc_models --cov=soc_normalization --cov=splunk_connector --cov=splunk_triage --cov=soc_correlation --cov-report=term-missing
```

An earlier milestone had **19 passing tests and 96% statement coverage** for the original modules. The newly added modules have additional local tests, but the full updated count and coverage should be taken from the latest GitHub Actions run, not the historical 96% figure.

## Project map

| Path | Purpose |
| --- | --- |
| `detection_rules.py` | Detect PowerShell encoded-command indicators |
| `triage.py` | Decode and triage evidence without executing payloads |
| `soc_models.py` | Validated alert and evidence contracts |
| `soc_normalization.py` | Convert Sysmon and 4104 fields to evidence |
| `splunk_connector.py` | Fetch bounded live detection results from Splunk |
| `splunk_triage.py` | Build `AlertEnvelope` from real Splunk events |
| `soc_correlation.py` | Enrich process and script block evidence |
| `test_*.py` | Reproducible offline regression tests |
| `docs/PROJECT_STATUS.md` | Verified status and current limitations |
| `docs/LAB_FIELD_REPORT_2026-11-10.md` | Field report, troubleshooting and reproducibility |

## Roadmap

- Original Python SOC models, detection and initial CI: completed.
- Lab telemetry/Splunk normalization, REST export, Python triage/correlation: validated in the private lab, with explicit caveats on missing evidence.
- Next: FastAPI integration, persistent backend data and integration tests; later AI-assisted investigation and React frontend.

[Actions](https://github.com/rolandohin/ai_powered_soc_lab/actions)
