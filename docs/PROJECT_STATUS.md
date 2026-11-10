# AI-Powered SOC Lab — Status

Last reviewed: 2026-11-10. Source of truth: GitHub main after the publication commit.

## Confirmed in the actual local lab (user-run)

- Proxmox VE with Ubuntu Splunk server and Windows 11 WIN-LAB installed.
- Sysmon and PowerShell Operational events forwarded to Splunk `winlab` index.
- XML event fields extracted automatically; Sysmon field aliases normalized in Splunk.
- Benign encoded PowerShell execution observed: Sysmon EID 1 and PowerShell EID 4104.
- SPL detection of encoded PowerShell executed, and search results rendered as JSON.
- Splunk management REST API (8089) reachable and successfully authenticated (HTTP 200).
- Search export returned real records to Windows PowerShell; Python connector retrieved real data.
- Real records passed into `AlertEnvelope` and triage; correlation executed against Splunk.
- Some alerts showed `missing_evidence: []`; at least one older detection retained `parent_process_event`. The reason was **not conclusively established**; older parent creation before Sysmon collection is a plausible explanation.

## Verified by offline/local tests

- Earlier baseline: 19 tests and 96% statement coverage in the original milestone.
- Additional test modules: 4 tests for Splunk triage and 11 for correlation, reported locally as passing.
- Total test count and **updated** coverage must be verified by the next GitHub Actions run. Do not present 96% as updated coverage for the new modules.

## Not yet implemented / not validated

- Persisted alert store or FastAPI REST and WebSocket endpoints.
- Fully autonomous AI agent, RAG, frontend dashboard, automated remediation.
- Production-grade Splunk TLS and least-privilege API service account.
- Complete correlation in every case; current Sysmon/Powershell 4104 PID/time approach is heuristic, with bounded query and fragment limits.

## Next

1. Push current verified source and offline tests without any secrets or raw telemetry.
2. Verify GitHub Actions on the new commit and fix any CI regressions.
3. Begin FastAPI backend (step 10) only after the source and tests are versioned.
