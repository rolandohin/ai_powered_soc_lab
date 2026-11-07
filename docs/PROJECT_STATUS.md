# AI-Powered SOC Lab — Project status

Last updated 2026-11-07

| Stage | Status | Evidence |
| --- | --- | --- |
| 1. PowerShell analysis and initial detection | VALIDATED | CLI demo and detection tests for encoded PowerShell |
| 2. SOC data model and event normalization | VALIDATED | v0.1 schema and synthetic integration test combining Sysmon and PowerShell 4104 |
| 3. Automated tests, coverage, and CI | VALIDATED | Windows baseline of 19 passing tests and 96% statement coverage reported locally. GitHub Actions workflow configured and a successful run confirmed |
| 4. Feasibility and architecture | IN_PROGRESS | Architecture and ADR drafted. Host inventory and feasibility measurements pending |

## Next action

Confirm the lab host, hypervisor, available RAM, and disk. Use this inventory to evaluate the proposed VM allocations in the [architecture notes](ARCHITECTURE.md), then record resource measurements during the first pilot. Live collection and Splunk ingestion remain upcoming work.
