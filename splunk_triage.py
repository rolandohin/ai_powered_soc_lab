"""Bridge live Splunk Sysmon detections to the existing SOC alert and triage models.

Read-only lab integration. No credentials or event data are written to disk.
Run from the repository root alongside splunk_connector.py, soc_models.py,
soc_normalization.py, detection_rules.py, and triage.py.
"""

import argparse
import getpass
import json
import ssl
import sys
from collections.abc import Mapping
from urllib.error import HTTPError, URLError

from detection_rules import detect_powershell_signals
from soc_models import AlertEnvelope
from soc_normalization import normalize_sysmon_process_create
from splunk_connector import fetch_detections
from triage import build_triage_result


RULE_ID = "powershell_encoded_command"


def build_alert_envelope(row: Mapping[str, str], *, instance_id: str = "lab") -> AlertEnvelope:
    """Validate a Splunk Event ID 1 detection and create a real SOC alert envelope."""
    required = ("host", "EventID", "UtcTime", "ProcessGuid", "Image", "CommandLine")
    missing = [key for key in required if not str(row.get(key, "")).strip()]
    if missing:
        raise ValueError(f"Missing required Splunk fields: {', '.join(missing)}")
    if str(row["EventID"]) != "1":
        raise ValueError("Only Sysmon Event ID 1 can be normalized by this integration")

    evidence_id = f"sysmon:{row['host']}:{row['ProcessGuid']}"
    source_ref = f"splunk:winlab:{row['host']}:{row['ProcessGuid']}"
    evidence = normalize_sysmon_process_create(
        row,
        evidence_id=evidence_id,
        source_ref=source_ref,
    )

    # Never accept every ProcessCreate as a detection: recheck with the
    # project's existing Python rule before building the alert.
    if RULE_ID not in detect_powershell_signals(evidence.model_dump(mode="json")):
        raise ValueError("Event does not match the PowerShell EncodedCommand detection")

    return AlertEnvelope.model_validate({
        "schema_version": "0.1",
        "synthetic": False,
        "alert": {
            "source": "splunk",
            "instance_id": instance_id,
            "alert_id": evidence_id,
            "rule_id": RULE_ID,
            "rule_version": "draft",
            "timestamp": evidence.timestamp,
            "host_id": row["host"],
            "event_refs": [source_ref],
        },
        "evidence": [evidence.model_dump(mode="json")],
        # These are not yet collected/correlated by this connector; their
        # presence or absence in Splunk has NOT been established.
        "missing_evidence": ["parent_process_event", "powershell_script_block"],
    })


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local SOC triage on real Splunk Sysmon detections")
    parser.add_argument("--host", default="192.168.1.25", help="Splunk server hostname/IP")
    parser.add_argument("--user", default="admin", help="Splunk API user")
    parser.add_argument("--instance-id", default="lab", help="Identifier for this Splunk instance")
    parser.add_argument("--ca-file", help="Trusted CA certificate bundle for TLS verification")
    parser.add_argument("--insecure-lab", action="store_true", help="Disable TLS verification only for a private lab")
    args = parser.parse_args()

    if args.insecure_lab and args.ca_file:
        parser.error("Choose either --ca-file or --insecure-lab")

    tls_context = (ssl._create_unverified_context() if args.insecure_lab
                   else ssl.create_default_context(cafile=args.ca_file))
    password = getpass.getpass("Mot de passe Splunk (non affiché) : ")

    try:
        rows = fetch_detections(args.host, args.user, password, context=tls_context)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Erreur lors de la recherche Splunk : {exc}", file=sys.stderr)
        return 1

    print(f"Événements Splunk reçus : {len(rows)}", file=sys.stderr)
    if not rows:
        print("Aucune détection sur les dernières 24 heures. Relance le scénario WIN-LAB.", file=sys.stderr)
        return 2

    valid_results = []
    for index, row in enumerate(rows, start=1):
        try:
            envelope = build_alert_envelope(row, instance_id=args.instance_id)
            triage = build_triage_result(envelope.model_dump(mode="json"))
        except (ValueError, KeyError, TypeError) as exc:
            print(f"Événement {index} écarté : {exc}", file=sys.stderr)
            continue
        valid_results.append({
            "alert_envelope": envelope.model_dump(mode="json"),
            "triage": triage,
        })

    print(json.dumps(valid_results, ensure_ascii=False, indent=2))
    print(f"Alertes validées et triées : {len(valid_results)}", file=sys.stderr)
    return 0 if valid_results else 2


if __name__ == "__main__":
    raise SystemExit(main())
