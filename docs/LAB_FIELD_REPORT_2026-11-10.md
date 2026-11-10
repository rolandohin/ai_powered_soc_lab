# Field report — from Windows events to correlated SOC evidence

**Date:** 2026-11-10  
**Lab:** Windows 11 + Sysmon + PowerShell Operational → Splunk Enterprise on Ubuntu/Proxmox → Python triage/correlation.  
**Scope:** benign local testing, not a production attack detection deployment.

## Objective

Move beyond a synthetic PowerShell alert: collect real events, extract fields, detect a suspicious invocation, retrieve events over a REST API and correlate supporting evidence without inventing missing records.

## Reproducible walkthrough

1. Confirm Windows Sysmon and PowerShell events are present:

```spl
index=winlab
| stats count by sourcetype
```

2. Inspect raw Sysmon XML:

```spl
index=winlab sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| head 1
| table _raw
```

3. Extract the Sysmon fields using search-time `rex` as a diagnosis, then configure permanent search-time extraction in Splunk `props.conf`. Preserve `_raw`; use `FIELDALIAS` for normalized names. Example:

```ini
[XmlWinEventLog:Microsoft-Windows-Sysmon/Operational]
EXTRACT-sysmon_eventid = <EventID>(?<EventID>[0-9]+)</EventID>
EXTRACT-sysmon_processguid = <Data Name='ProcessGuid'>(?<ProcessGuid>[^<]*)</Data>
EXTRACT-sysmon_image = <Data Name='Image'>(?<Image>[^<]*)</Data>
EXTRACT-sysmon_commandline = <Data Name='CommandLine'>(?<CommandLine>[^<]*)</Data>
FIELDALIAS-soc_event = EventID AS EventCode
```

4. Generate benign PowerShell test telemetry on WIN-LAB:

```powershell
$script = "Write-Output 'SOC-LAB'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($script))
powershell.exe -NoProfile -EncodedCommand $encoded
```

5. Detect encoded command usage in Splunk:

```spl
index=winlab sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| where match(Image, "(?i)(powershell|pwsh)\.exe$")
| rex field=CommandLine "(?i)-(?<encoded_switch>EncodedCommand|ec|e)\s+"
| where isnotnull(encoded_switch)
| table _time host Image ParentImage CommandLine ProcessGuid ParentProcessGuid encoded_switch
```

6. The Splunk REST search API (`/services/search/v2/jobs/export`) returned real records as JSON. `splunk_connector.py` uses a bounded query, `splunk_triage.py` builds `AlertEnvelope(synthetic=false)`, and `soc_correlation.py` enriches evidence using Sysmon `ProcessGuid` and PowerShell 4104.

## Difficulties and lessons

**XML extraction:** `host` appeared, but EventID, Image, ParentImage and CommandLine were blank in a normal Splunk table. The fields were present in `_raw`. `rex` confirmed them, and `props.conf`/`FIELDALIAS` made extraction reusable. This was a search-time parsing issue, not missing events.

**SPL queries returning zero:** narrow regexes and filters initially suppressed matches even when data existed. We reduced the query to an independent raw token search and added filters progressively. Never assume an empty query means no event exists.

**API versus Web:** TCP/8089 and HTTP 200 validated authenticated REST connectivity; this is distinct from Splunk Web on port 8000. The project currently uses insecure TLS *only with explicit `--insecure-lab` in a private lab*. A trusted CA and least-privilege API role are still required before wider use.

**Missing parent evidence:** some correlation results included `parent_process_event` in `missing_evidence`; other alerts had `[]`. A parent created before Sysmon became active is plausible, but not conclusively proven for the unmatched record. Missing evidence is preserved rather than silently discarded.

**4104 correlation limitations:** correlation uses host + PID + time and confirms complete script-block fragments. This remains a heuristic due to PID reuse, logging gaps, clock drift, time-window caps and fragment caps. More identity checks are needed for production use.

## Validation claims

- **Lab-validated:** XML field extraction, live Sysmon/4104 collection, benign encoded-command telemetry, SPL results/JSON, REST authentication/export, Python real-event triage, some full evidence correlations.
- **Offline-tested:** Python data models, decoding, triage and the new unit test cases. Earlier milestone reported 19 tests / 96% statement coverage; four Splunk triage and eleven correlation tests later passed locally. The next Actions run must establish the new whole-project count/coverage.
- **Not validated:** a production detection rule, causation for the specific missing parent, live FastAPI backend, dashboard, LLM agent, or response automation.

## Operational and publication safety

Do not commit API credentials, tokens, `.env` files, raw 4104 script content, identity data, certificates/private keys, incident artifacts or unredacted JSON exports. Only publish synthetic fixtures and anonymized examples; review screenshots for IP, usernames and sensitive process command lines.

## Follow-on

Push these sources and tests; confirm GitHub Actions is green; then implement FastAPI in step 10.
