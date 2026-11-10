"""Read a small sample of live Sysmon PowerShell detections from Splunk.

Lab-only smoke test: this module does not yet build an AlertEnvelope or
persist retrieved events. The API username/password are never written to disk.
"""

import argparse
import base64
import getpass
import json
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


SPL = r'''search index=winlab sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| where EventID="1"
| where match(Image, "(?i)(powershell|pwsh)\.exe$")
| rex field=CommandLine "(?i)-(?<encoded_switch>EncodedCommand|ec|e)\s+"
| where isnotnull(encoded_switch)
| sort - _time
| head 5
| table _time host EventID UtcTime Image ParentImage CommandLine ProcessGuid ParentProcessGuid ProcessId ParentProcessId User encoded_switch'''


def fetch_detections(host: str, user: str, password: str, *, context: ssl.SSLContext) -> list[dict]:
    """POST a bounded SPL search and parse Splunk's newline-delimited JSON."""
    url = f"https://{host}:8089/services/search/v2/jobs/export"
    form_data = urlencode({
        "search": SPL,
        "earliest_time": "-24h",
        "latest_time": "now",
        "output_mode": "json",
    }).encode("utf-8")
    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    request = Request(
        url,
        data=form_data,
        method="POST",
        headers={
            "Authorization": f"Basic {token}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    detections = []
    with urlopen(request, context=context, timeout=60) as response:
        for raw_line in response:
            if not raw_line.strip():
                continue
            record = json.loads(raw_line)
            if record.get("preview") is True:
                continue
            if isinstance(record.get("result"), dict):
                detections.append(record["result"])
    return detections


def main() -> int:
    parser = argparse.ArgumentParser(description="Test a read-only Splunk → Python connector")
    parser.add_argument("--host", default="192.168.1.25", help="Splunk server IP or hostname")
    parser.add_argument("--user", default="admin", help="Splunk API user")
    parser.add_argument("--ca-file", help="CA bundle to verify Splunk's TLS certificate")
    parser.add_argument("--insecure-lab", action="store_true", help="Disable TLS verification ONLY for a trusted lab")
    args = parser.parse_args()

    if args.insecure_lab and args.ca_file:
        parser.error("Choose either --ca-file or --insecure-lab, not both")
    context = (ssl._create_unverified_context() if args.insecure_lab
               else ssl.create_default_context(cafile=args.ca_file))
    password = getpass.getpass("Mot de passe Splunk (non affiché) : ")

    try:
        results = fetch_detections(args.host, args.user, password, context=context)
    except HTTPError as exc:
        print(f"Erreur HTTP Splunk : {exc.code} {exc.reason}", file=sys.stderr)
        return 1
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Erreur de connexion ou de réponse : {exc}", file=sys.stderr)
        return 1

    print(f"Détections reçues : {len(results)}")
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
