# Field report — from Windows events to correlated SOC evidence

**Date:** 2026-11-10  
**Lab:** Windows 11 + Sysmon + PowerShell Operational → Splunk Enterprise on Ubuntu/Proxmox → Python triage/correlation.  
**Scope:** benign local testing, not a production attack detection deployment.

## Objective

Move beyond a synthetic PowerShell alert: collect real events, extract fields, detect a suspicious invocation, retrieve events over a REST API and correlate supporting evidence without inventing missing records.

## Reproducible walkthrough

1. Check that the Splunk Universal Forwarder service has permission to read the Sysmon channel. This is a distinct issue from forwarding or SPL extraction. In the lab, the Sysmon events were visible locally on Windows, and PowerShell logs reached Splunk, while Sysmon logs did not. The Universal Forwarder service ran under `NT SERVICE\SplunkForwarder`. The channel's security descriptor granted read access to the built-in **Event Log Readers** group (SID `S-1-5-32-573`), but that service identity was not a member.

Run in **Windows PowerShell as Administrator on WIN-LAB**, after confirming the service account:

```powershell
Get-CimInstance Win32_Service -Filter "Name='SplunkForwarder'" | Select-Object Name, StartName
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Select-Object LogName, IsEnabled, SecurityDescriptor
Get-LocalGroupMember -SID 'S-1-5-32-573'
```

The corrective command used in this lab was:

```powershell
Add-LocalGroupMember -SID 'S-1-5-32-573' -Member 'NT SERVICE\SplunkForwarder' -ErrorAction Stop
Restart-Service SplunkForwarder
```

Verify membership and incoming Sysmon events:

```powershell
Get-LocalGroupMember -SID 'S-1-5-32-573' | Where-Object Name -like '*SplunkForwarder*'
```

```spl
index=winlab sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count
```

**Identity clarification:** The account granted membership was `NT SERVICE\SplunkForwarder`, **not** `NT AUTHORITY\SYSTEM` (`S-1-5-18`). `NT SERVICE\SplunkForwarder` is the Windows service account used in this setup; the correct fix depends on the actual `StartName` and channel ACL. Do not add unrelated identities to broad groups or change permissions blindly. Record this access-control fix separately from search-time field extraction.

2. Confirm Windows Sysmon and PowerShell events are present:

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
EXTRACT-sysmon_originalfilename = <Data Name='OriginalFileName'>(?<OriginalFileName>[^<]*)</Data>
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

**Sysmon permission denied to the forwarder:** Sysmon Event ID 1 existed locally while Splunk received PowerShell events but not Sysmon. The channel ACL allowed Event Log Readers (SID `S-1-5-32-573`), so the service identity `NT SERVICE\SplunkForwarder` was added to that group, and the service was restarted. The collector could then forward Sysmon logs. This was a **read-access issue**, distinct from the later XML extraction problem.

**XML extraction:** `host` appeared, but EventID, Image, ParentImage and CommandLine were blank in a normal Splunk table. The fields were present in `_raw`. `rex` confirmed them, and `props.conf`/`FIELDALIAS` made extraction reusable. This was a search-time parsing issue, not missing events.

**SPL queries returning zero:** narrow regexes and filters initially suppressed matches even when data existed. We reduced the query to an independent raw token search and added filters progressively. Never assume an empty query means no event exists.

**API versus Web:** TCP/8089 and HTTP 200 validated authenticated REST connectivity; this is distinct from Splunk Web on port 8000. The project currently uses insecure TLS *only with explicit `--insecure-lab` in a private lab*. A trusted CA and least-privilege API role are still required before wider use.

**Missing parent evidence:** some correlation results included `parent_process_event` in `missing_evidence`; other alerts had `[]`. A parent created before Sysmon became active is plausible, but not conclusively proven for the unmatched record. Missing evidence is preserved rather than silently discarded.

**4104 correlation limitations:** correlation uses host + PID + time and confirms complete script-block fragments. This remains a heuristic due to PID reuse, logging gaps, clock drift, time-window caps and fragment caps. More identity checks are needed for production use.

## Validation claims

- **Lab-validated:** Sysmon channel read-permission fix for `NT SERVICE\SplunkForwarder`, XML field extraction, live Sysmon/4104 collection, benign encoded-command telemetry, SPL results/JSON, REST authentication/export, Python real-event triage, some full evidence correlations.
- **Offline-tested:** Python data models, decoding, triage and the new unit test cases. Earlier milestone reported 19 tests / 96% statement coverage; four Splunk triage and eleven correlation tests later passed locally. The next Actions run must establish the new whole-project count/coverage.
- **Not validated:** a production detection rule, causation for the specific missing parent, live FastAPI backend, dashboard, LLM agent, or response automation.

## Operational and publication safety

Do not commit API credentials, tokens, `.env` files, raw 4104 script content, identity data, certificates/private keys, incident artifacts or unredacted JSON exports. Only publish synthetic fixtures and anonymized examples; review screenshots for IP, usernames and sensitive process command lines.

## Follow-on

Push these sources and tests; confirm GitHub Actions is green; then implement FastAPI in step 10.

## Update 2026-11-22 — EncodedCommand evasion and renamed PowerShell

**Problem.** The original rule only matched `-EncodedCommand`, `-ec` and `-e`, and only when `Image` ended with `powershell.exe` or `pwsh.exe`. PowerShell accepts any unambiguous parameter prefix (`-enc`, `-encod`, ...), so common variants were missed. A renamed copy of `powershell.exe` bypassed the `Image` check (MITRE ATT&CK T1036.003). The Splunk SPL had the same blind spots, so events were dropped before reaching Python.

**Changes.**
- `detection_rules.py`: all prefixes of `EncodedCommand` plus `ec`; `-`, `/`, en dash, em dash and horizontal bar as parameter prefix; PowerShell identified by `Image` **or** Sysmon `OriginalFileName`.
- `splunk_connector.py`: the SPL pre-filter is generated from the same Python constants, so Splunk and Python cannot drift apart. Python stays the authority.
- `soc_normalization.py`: `OriginalFileName` is carried into evidence as `original_file_name`.
- `test_detection_rules.py`: versioned evasion corpus (14 true positives, 8 false-positive traps). Replayed offline against the previous regex, it missed 11 of 14 true positives.
- `test_splunk_connector.py`: the generated SPL regex is checked against the same corpus.

**Lab procedure (WIN-LAB, benign payload only).**

```powershell
$cmd = "Write-Output 'SOC-LAB-EVASION-TEST'"
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -enc $b64
powershell.exe -NoProfile /enc $b64
powershell.exe -NoProfile ([char]0x2013 + 'enc') $b64
$renamed = Join-Path $env:TEMP 'notepad-soclab-test.exe'
Copy-Item "$PSHOME\powershell.exe" $renamed
& $renamed -NoProfile -enc $b64
Remove-Item $renamed
```

**Difficulty: `OriginalFileName` was always null.** Sysmon wrote the field (verified with `Get-WinEvent` on WIN-LAB), but Splunk extracts Sysmon fields through explicit `EXTRACT-` rules in `props.conf`, and none existed for `OriginalFileName`. Adding `EXTRACT-sysmon_originalfilename` fixed it. Because the extraction runs at search time, already-indexed events gained the field without replaying the scenario.

**Validation claims.**
- **Lab-validated:** Windows PowerShell executed `-enc`, `/enc` and en-dash `–enc`; all three were returned by the generated SPL and decoded by `splunk_triage.py`. Sysmon logged the renamed copy with `OriginalFileName = PowerShell.EXE`. After the `props.conf` change, `original_file_name` is populated in triage output.
- **Offline-tested:** evasion corpus, SPL/Python parity, renamed-PowerShell envelope, fixture sanitization.
- **Not validated:** em dash and horizontal bar prefixes; `pwsh.dll` as PowerShell 7 `OriginalFileName`; behavior when more than `head 5` matching events exist in the time window.
