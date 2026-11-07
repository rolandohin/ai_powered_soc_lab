# ADR 0001 — Use export-based triage for the first live scenario

**Status** Proposed

## Context

The lab already has a validated CLI, a versioned alert model, and tests for Sysmon and PowerShell evidence. The next architecture must connect those pieces to a controlled Windows scenario and let the analyst reproduce a result with traceable evidence.

## Options

| Option | Benefit | Trade-off |
| --- | --- | --- |
| A. Splunk exports and deterministic Python triage | Reuses the existing CLI. Runs offline against a recorded fixture and supports repeatable comparisons | Export and replay are manual. Time from alert to report depends on the operator |
| B. Splunk webhook and deterministic worker | Automates intake and preserves the same evidence contract | Needs authentication, durable storage, deduplication, bounded retries, and failure visibility |
| C. Automated intake with optional LLM assistance | May help synthesize a larger dossier once the evidence pipeline is reliable | Adds model latency, cost, evaluation work, and exposure to untrusted text in logs |

## Decision

Start with **option A** for the first live scenario. Establish a deterministic baseline with an encoded test, a benign control, and an incomplete-evidence case. Keep the alert and evidence contract stable so a future worker can reuse it.

Revisit option B after a live pilot measures ingestion delay and search latency and a replay demonstrates provenance from Windows to the triage report. Evaluate option C separately against labeled cases, measuring verdict agreement, unsupported claims, abstention, latency, and cost. The deterministic report remains the comparison baseline.
