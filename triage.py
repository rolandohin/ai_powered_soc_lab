import json
from pathlib import Path
import base64
import re

alert_path = Path(__file__).resolve().parent / "fixtures" / "alert.json"
data = json.loads(alert_path.read_text(encoding="utf-8-sig"))

alert = data["alert"]

print(f"Alert: {alert['alert_id']}")
print(f"Rule: {alert['rule_id']}")
print(f"Host: {alert['host_id']}")
print(f"Time: {alert['timestamp']}")

for event in data["evidence"]:
    print(f"\nEvidence: {event['id']} ({event['type']})")
    print(f"Parent process: {event['parent_image']}")
    print(f"Process: {event['image']}")
    print(f"Command line: {event['command_line']}")
    match = re.search(r"-EncodedCommand\s+(\S+)", event["command_line"], re.IGNORECASE)
    if match:
        encoded_command = match.group(1)
        decoded_bytes = base64.b64decode(encoded_command, validate=True)
        decoded_command = decoded_bytes.decode("utf-16-le")
        print(f"Decoded command: {decoded_command}")

print("\nMissing evidence:")
for item in data["missing_evidence"]:
    print(f"- {item}")