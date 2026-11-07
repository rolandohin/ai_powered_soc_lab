# AI-Powered SOC Lab

A hands-on SOC engineering lab for building detections and investigating alerts with traceable evidence. The first working scenario triages encoded PowerShell invocations using synthetic Windows telemetry.

## What works today

- Detects `-EncodedCommand`, `-e`, and `-ec` on PowerShell process events. It decodes Base64 as UTF-16LE and reports the decoded text without executing it.
- Validates alerts against a versioned data model, normalizes timestamps to UTC, and keeps source references and missing evidence visible.
- Normalizes pre-extracted fields from Sysmon process creation (Event ID 1) and PowerShell Script Block Logging (Event ID 4104). An integration test checks that both types of evidence can coexist in one alert.
- Runs automated tests and reports coverage on Windows with Python 3.14 through [GitHub Actions](https://github.com/rolandohin/ai_powered_soc_lab/actions).

## Run the PowerShell triage demo

From PowerShell with Python 3.14 available:

```powershell
git clone https://github.com/rolandohin/ai_powered_soc_lab.git
cd ai_powered_soc_lab
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe .\triage.py --json
```

The bundled alert `lab-001` contains a synthetic Sysmon process event. Its evidence entry should include:

```json
{
  "signals": ["powershell_encoded_command"],
  "decode_status": "decoded",
  "decoded_command": "Write-Output 'SOC-LAB'"
}
```

The decoded command is benign in this scenario. An invalid payload can still trigger the detection signal and return `decode_status: failed`. In the bundled alert, the parent process event and the PowerShell script block are listed as missing. The separate integration test supplies both a Sysmon event and a synthetic 4104 event.

## Run tests and coverage

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -v --cov=triage --cov=detection_rules --cov=soc_models --cov=soc_normalization --cov-report=term-missing
```

The suite covers detection, decoding, model validation, event normalization, and the CLI's text and JSON output. The stage 3 baseline was 19 passing tests and 96% statement coverage in a local Windows run.

## Project map

| Path | Purpose |
| --- | --- |
| [`triage.py`](triage.py) | Loads and validates the sample alert, then produces a text or JSON report |
| [`detection_rules.py`](detection_rules.py) | Identifies encoded PowerShell invocations |
| [`soc_models.py`](soc_models.py) | Defines the alert and evidence models |
| [`soc_normalization.py`](soc_normalization.py) | Converts source event fields to the evidence model |
| [`schemas/alert-envelope-0.1.schema.json`](schemas/alert-envelope-0.1.schema.json) | Describes the input contract for version 0.1 |
| [`fixtures/alert.json`](fixtures/alert.json) | Provides the synthetic alert for the CLI demo |

## Roadmap

| Stage | Status |
| --- | --- |
| 1. PowerShell analysis and initial detection | Complete |
| 2. SOC data model and event normalization | Complete |
| 3. Automated tests, coverage, and CI | Complete |
| 4. Feasibility and architecture | In progress |
| Live Windows telemetry and Splunk ingestion | Planned |
| AI-assisted investigation and analyst dashboard | Planned |

See the [architecture notes](docs/ARCHITECTURE.md) and [project status](docs/PROJECT_STATUS.md).
