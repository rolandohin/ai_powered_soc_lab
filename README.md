# AI-Powered SOC Lab

A hands-on SOC engineering lab to build reproducible detection, normalization and triage workflows using both synthetic and real Windows telemetry.

## Current working scope (November 2026)

- Python detection and UTF-16LE/Base64 decoding of PowerShell `-EncodedCommand` and every unambiguous abbreviation (`-e`, `-ec`, `-enc`, ...), with `-`, `/` or Unicode dash prefixes; renamed `powershell.exe` is identified through Sysmon `OriginalFileName`. Decoded payloads are **not executed**.
- FastAPI service with a `GET /health` liveness probe (step 10).
- Versioned SOC `AlertEnvelope`/`Evidence` models with timestamp normalization and explicit `missing_evidence`.
- Read-only Splunk REST connector with bounded Sysmon searches, real-event alert construction and local triage.
- Correlation against Sysmon parent `ProcessGuid` and PowerShell Event 4104 script-block fragments. Missing parent/script evidence is reported instead of inferred.
- Offline Python tests; GitHub Actions executes them on pushes and pull requests to `main` and supports manual runs.

**Not built yet:** triage and Splunk endpoints in the API, authentication, WebSocket updates, persistent alerts, agentic AI/RAG investigation, dashboard, and automatic response/remediation.

## Architecture

WIN-LAB (Windows 11, Sysmon, PowerShell 4104) → Splunk Universal Forwarder → Splunk on Ubuntu/Proxmox → bounded REST API searches → Python SOC normalization, correlation and triage.

## Windows Sysmon collection troubleshooting

During setup, Sysmon events existed locally but were absent from Splunk while PowerShell events arrived. The Splunk Universal Forwarder service ran as `NT SERVICE\SplunkForwarder`; membership in the built-in Event Log Readers group (SID `S-1-5-32-573`) was required for the observed Sysmon channel ACL. On WIN-LAB, the lab fix was:

```powershell
# Run as Administrator; verify the Forwarder service identity first.
Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" | Select-Object Name, StartName
Add-LocalGroupMember -SID 'S-1-5-32-573' -Member 'NT SERVICE\SplunkForwarder' -ErrorAction Stop
Restart-Service SplunkForwarder
```

This was **not** an instruction to add `NT AUTHORITY\SYSTEM` to a group. It is only appropriate for the service identity and security descriptor observed in this lab. The complete diagnostic and reproduction steps are in [`docs/LAB_FIELD_REPORT_2026-11-10.md`](docs/LAB_FIELD_REPORT_2026-11-10.md).

## Quick start: offline demonstration

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe .\triage.py --json
.\.venv\Scripts\python.exe -m pytest -v
```

Use test fixtures for CI; do not require live credentials or a Splunk server for automated unit tests.

## Run the API

The API exposes the SOC Lab engine over HTTP. It currently provides a liveness probe only.

```powershell
python -m uvicorn api.main:app --host 127.0.0.1 --port 8001 --reload
```

- `GET /health` returns `{"status": "ok", "service": "ai-powered-soc-lab", "version": "0.1.0"}`.
- Interactive documentation: `http://127.0.0.1:8001/docs`.
- The server binds to `127.0.0.1` only. Do not expose it on the lab network before authentication is in place (roadmap step 15).
- `/health` is a liveness probe: it deliberately checks no dependency (Splunk, database).

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
python -m pytest -v --cov=triage --cov=detection_rules --cov=soc_models --cov=soc_normalization --cov=splunk_connector --cov=splunk_triage --cov=soc_correlation --cov=sanitize_fixture --cov=api --cov-report=term-missing

Latest verified GitHub Actions run (PR #2, detection hardening): 96 tests passed, 73% total coverage. Lowest coverage is in network-facing code (`splunk_connector`, `splunk_triage`), whose live Splunk paths are validated in the lab rather than in CI. Check [Actions](https://github.com/rolandohin/ai_powered_soc_lab/actions) for the current run.

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
| `test_*.py` | Reproducible offline regression tests, including the evasion corpus in `test_detection_rules.py` |
| `docs/PROJECT_STATUS.md` | Verified status and current limitations |
| `docs/LAB_FIELD_REPORT_2026-11-10.md` | Field report, troubleshooting and reproducibility |
| `api/main.py` | FastAPI application and `GET /health` |
| `sanitize_fixture.py` | Replace lab identifiers in XML fixtures before committing them |
| `fixtures/` | Sanitized event samples for offline tests |

## Roadmap

- Original Python SOC models, detection and initial CI: completed.
- Lab telemetry/Splunk normalization, REST export, Python triage/correlation: validated in the private lab, with explicit caveats on missing evidence.
- Detection hardening (EncodedCommand evasion, renamed PowerShell): validated in the lab and in CI.
- FastAPI foundation with `GET /health` (step 10): done.
- Next: `POST /triage` (step 11), Splunk endpoint, persistence, alert lifecycle and API security; later AI-assisted investigation and React frontend.

[Actions](https://github.com/rolandohin/ai_powered_soc_lab/actions)
