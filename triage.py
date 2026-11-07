import json
from pathlib import Path
import base64
import re
import binascii
import argparse
from detection_rules import detect_powershell_signals
from detection_rules import ENCODED_COMMAND_OPTION


def decode_powershell_payload(encoded_command: str) -> str:
        decoded_bytes = base64.b64decode(encoded_command, validate=True)
        return decoded_bytes.decode("utf-16-le")

def build_triage_result(data: dict) -> dict:
    evidence = []

    for event in data["evidence"]:
        result = {
            **event,
            "signals": detect_powershell_signals(event),
            "decode_status": "not_present",
            "decoded_command": None,
        }

        match = re.search(
            ENCODED_COMMAND_OPTION + r"\s+(\S+)",
            event.get("command_line") or "",
            re.IGNORECASE,
        )

        if match:
            try:
                result["decoded_command"] = decode_powershell_payload(match.group(1))
            except ValueError:
                result["decode_status"] = "failed"
            else:
                result["decode_status"] = "decoded"

        evidence.append(result)

    return {
        "alert": data["alert"],
        "evidence": evidence,
        "missing_evidence": data["missing_evidence"],
    }

def main():
    alert_path = Path(__file__).resolve().parent / "fixtures" / "alert.json"
    data = json.loads(alert_path.read_text(encoding="utf-8-sig"))
    parser = argparse.ArgumentParser(description="Triage a PowerShell lab alert")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    result = build_triage_result(data)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    alert = result["alert"]
    print(f"Alert: {alert['alert_id']}")
    print(f"Rule: {alert['rule_id']}")
    print(f"Host: {alert['host_id']}")
    print(f"Time: {alert['timestamp']}")

    for event in result["evidence"]:
        print(f"\nEvidence: {event['id']} ({event['type']})")
        print(f"Parent process: {event['parent_image']}")
        print(f"Process: {event['image']}")
        print(f"Command line: {event['command_line']}")
        if event["decode_status"] == "decoded":
                    print(f"Decoded command: {event['decoded_command']}")
        elif event["decode_status"] == "failed":
                    print("Decode status: Failed to decode PowerShell command")

    print("\nMissing evidence:")
    for item in data["missing_evidence"]:
        print(f"- {item}")

if __name__ == "__main__":
    main()