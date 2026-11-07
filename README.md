# AI-Powered SOC Lab

A hands-on lab for practicing SOC detection engineering and alert triage.

## Project scope

- Collect and analyze Windows and PowerShell telemetry.
- Build and validate detections against controlled lab scenarios.
- Explore AI-assisted alert triage with human review.

## Status

The lab is in development. The first planned scenario focuses on suspicious PowerShell execution.

## PowerShell triage demo

Run the demo and its tests from the repository root:

```powershell
python .\triage.py --json
python -m unittest -v
```

The synthetic alert `lab-001` should report the signal
`powershell_encoded_command` and decode the payload to `Write-Output 'SOC-LAB'`.

Detection and decoding are reported separately. An invalid Base64 value
can still trigger the signal, with `decode_status` set to `failed`.
The signal identifies an encoded invocation for review. Assessing whether
it is malicious requires context from the command and surrounding events.

The current tests cover `-EncodedCommand`, `-e`, and `-ec`. The demo uses
a synthetic alert and displays decoded text without executing it.