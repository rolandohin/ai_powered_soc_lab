# AI-Powered SOC Lab — Status

Last reviewed: 2026-11-22. Source of truth: GitHub `main` and its latest GitHub Actions run.

## Confirmed in the actual local lab (user-run)

- Proxmox VE with Ubuntu Splunk server and Windows 11 WIN-LAB installed.
- Sysmon and PowerShell Operational events forwarded to Splunk `winlab` index. Resolved initial Sysmon read-access failure by adding the actual Forwarder service identity `NT SERVICE\SplunkForwarder` to Event Log Readers (SID `S-1-5-32-573`) and restarting the service; this was not `NT AUTHORITY\SYSTEM`.
- XML event fields extracted at search time with explicit `EXTRACT-` rules in Splunk `props.conf` (see the field report); a field without its own rule, such as `OriginalFileName` before 2026-11-22, is not available in searches.
- Benign encoded PowerShell execution observed: Sysmon EID 1 and PowerShell EID 4104.
- SPL detection of encoded PowerShell executed, and search results rendered as JSON.
- Splunk management REST API (8089) reachable and successfully authenticated (HTTP 200).
- Search export returned real records to Windows PowerShell; Python connector retrieved real data.
- Real records passed into `AlertEnvelope` and triage; correlation executed against Splunk.
- Some alerts showed `missing_evidence: []`; at least one older detection retained `parent_process_event`. The reason was **not conclusively established**; older parent creation before Sysmon collection is a plausible explanation.

## Verified by offline/local tests

- GitHub Actions on PR #2 (windows-latest, Python 3.14): 96 tests passed, 73% total coverage.
- Includes the evasion corpus, SPL/Python parity tests, fixture leak checks, Splunk triage and correlation tests.
- Step 10 adds 4 API tests (`test_api_health.py`); the updated CI count will be recorded after its pull request.

## Not yet implemented / not validated

- Persisted alert store; API endpoints beyond `GET /health` (triage, Splunk), API authentication and WebSocket updates.
- Fully autonomous AI agent, RAG, frontend dashboard, automated remediation.
- Production-grade Splunk TLS and least-privilege API service account.
- Complete correlation in every case; current Sysmon/Powershell 4104 PID/time approach is heuristic, with bounded query and fragment limits.

## Next

## Next

1. Step 11: expose the triage engine through `POST /triage`, reusing `AlertEnvelope` as the request contract.
2. Step 12: Splunk-backed endpoint reusing `splunk_triage`, read-only and bounded.
3. Remove the private Splunk IP used as `--host` default in the scripts; read it from configuration instead.

## Detection hardening — EncodedCommand evasion (2026-11-22)

| Item | Status |
|---|---|
| EncodedCommand prefixes, `/` and en dash detected | Lab-validated |
| Renamed PowerShell detected via `OriginalFileName` | Lab-validated at source (Sysmon); requires `EXTRACT-sysmon_originalfilename` in Splunk `props.conf` |
| SPL generated from Python rule constants | In place, tested offline |
| Evasion corpus in CI | In place |
| Sanitized Sysmon EID 1 fixture + leak check in CI | In place |
| Em dash / horizontal bar, PowerShell 7 | Not validated |

Merged into `main` via pull request. GitHub Actions (windows-latest, Python 3.14): 96 tests passed, total coverage 73%. Lowest coverage is in network-facing code (`splunk_connector` 35%, `splunk_triage` 46%), whose live Splunk paths are validated in the lab, not in CI.

## Step 10 — FastAPI foundation (2026-11-22)

| Item | Status |
|---|---|
| Runtime dependencies pinned (`pydantic`, `fastapi`, `uvicorn`); `httpx` for tests | Done |
| `api/main.py` with `GET /health` liveness probe | Done, tested offline with `TestClient` |
| Server started on `127.0.0.1:8001`; `/health` and `/docs` checked in a browser | Lab-validated |
| API coverage tracked in CI (`--cov=api`) | In place |
