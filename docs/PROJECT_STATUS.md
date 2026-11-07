# AI-Powered SOC Lab — Project status

Last updated 2026-11-07

| Stage | Status | Evidence |
| --- | --- | --- |
| 1. PowerShell analysis and initial detection | VALIDATED | CLI demo and detection tests for encoded PowerShell |
| 2. SOC data model and event normalization | VALIDATED | v0.1 schema and synthetic integration test combining Sysmon and PowerShell 4104 |
| 3. Automated tests, coverage, and CI | VALIDATED | Windows baseline of 19 passing tests and 96% statement coverage reported locally. GitHub Actions workflow configured and a successful run confirmed |
| 4. Feasibility and architecture | IN_PROGRESS | Architecture and ADR drafted. The lab host has 16 GB of installed RAM, as reported by the project owner. The VM memory allocation is defined for the pilot |

## Next action

Initial allocation is 4 GB to `WIN-LAB`, 8 GB to `SOC-SIEM`, and approximately 4 GB for Proxmox and headroom. Confirm the CPU model, usable memory, and free storage after installing Proxmox. Measure memory and swap with both VMs active during the pilot. If the host shows sustained memory pressure, run collection and replay in separate sessions. See the [architecture notes](ARCHITECTURE.md).
