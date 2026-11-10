"""Enrich real Splunk Sysmon PowerShell detections with parent and script-block evidence.

Read-only lab connector for the AI-Powered SOC Lab repository. All searches are
bounded; no credentials are saved, no PowerShell commands are executed.

Requires the updated splunk_connector.py (includes ProcessId in detections).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import html
import json
import re
import ssl
import sys
from datetime import datetime, timedelta, timezone
from typing import Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from soc_models import AlertEnvelope
from soc_normalization import normalize_powershell_script_block, normalize_sysmon_process_create
from splunk_connector import fetch_detections
from splunk_triage import build_alert_envelope
from triage import build_triage_result


# This is lab-specific; tune the window and cap using actual lab volumes.
SCRIPT_WINDOW_BEFORE_SECONDS = 2
SCRIPT_WINDOW_AFTER_SECONDS = 300
MAX_SCRIPT_EVENTS = 100
MAX_PARENT_EVENTS = 2
_HOST_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_GUID_RE = re.compile(r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,38}\}?$")


def _timestamp(value: str | datetime) -> datetime:
    """UTC-aware event time; Sysmon UtcTime is UTC although usually no tz is set."""
    when = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if when.tzinfo is None:
        return when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc)


def _validate_host(host: str) -> str:
    if not _HOST_RE.fullmatch(host):
        raise ValueError("Unsafe or invalid Splunk host value")
    return host


def _validate_guid(guid: str) -> str:
    if not _GUID_RE.fullmatch(guid):
        raise ValueError("Invalid Sysmon ProcessGuid")
    return guid


def fetch_search(
    host: str, user: str, password: str, *, context: ssl.SSLContext,
    query: str, earliest: str, latest: str,
) -> list[dict]:
    """Read final results from Splunk's /export API (NDJSON), without previews."""
    url = f"https://{host}:8089/services/search/v2/jobs/export"
    data = urlencode({
        "search": query,
        "earliest_time": earliest,
        "latest_time": latest,
        "output_mode": "json",
    }).encode("utf-8")
    auth = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
    request = Request(url, data=data, method="POST", headers={
        "Authorization": "Basic " + auth,
        "Content-Type": "application/x-www-form-urlencoded",
    })
    rows: list[dict] = []
    with urlopen(request, timeout=60, context=context) as response:
        for line in response:
            if not line.strip():
                continue
            item = json.loads(line)
            if item.get("preview") is True:
                continue
            if isinstance(item.get("result"), dict):
                rows.append(item["result"])
    return rows


def parent_search_query(detection: Mapping[str, str]) -> str | None:
    """Use the GUID of the *parent*, never the parent's image or PID."""
    host = _validate_host(str(detection["host"]))
    guid = detection.get("ParentProcessGuid") or ""
    if not guid:
        return None
    guid = _validate_guid(str(guid))
    return (
        'search index=winlab sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" '
        f'host="{host}" '
        f'| where EventID="1" AND ProcessGuid="{guid}" '
        '| sort 0 - _time | head 2 '
        '| table _time host EventID UtcTime ProcessGuid ParentProcessGuid '
        'ProcessId ParentProcessId Image ParentImage CommandLine User'
    )


def script_search_query(detection: Mapping[str, str]) -> str | None:
    """Match 4104 process IDs; Python also verifies host and event timestamps."""
    host = _validate_host(str(detection["host"]))
    pid = str(detection.get("ProcessId") or "")
    if not pid.isdecimal():
        return None
    return (
        'search index=winlab sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" '
        f'host="{host}" '
        '| rex field=_raw "<EventID>(?<ps_event_id>[0-9]+)</EventID>" '
        '| where ps_event_id="4104" '
        '| rex field=_raw "<Execution ProcessID=\'(?<ps_pid>[0-9]+)\'" '
        f'| where ps_pid="{pid}" '
        '| rex field=_raw "<TimeCreated SystemTime=\'(?<system_time>[^\']+)\'" '
        '| rex field=_raw "<EventRecordID>(?<record_id>[0-9]+)</EventRecordID>" '
        '| rex field=_raw "<Data Name=\'ScriptBlockId\'>(?<ScriptBlockId>[^<]*)</Data>" '
        '| rex field=_raw "(?s)<Data Name=\'ScriptBlockText\'>(?<ScriptBlockText>.*?)</Data>" '
        '| rex field=_raw "<Data Name=\'MessageNumber\'>(?<MessageNumber>[0-9]+)</Data>" '
        '| rex field=_raw "<Data Name=\'MessageTotal\'>(?<MessageTotal>[0-9]+)</Data>" '
        f'| sort 0 _time | head {MAX_SCRIPT_EVENTS} '
        '| table host ps_pid system_time record_id ScriptBlockId ScriptBlockText MessageNumber MessageTotal'
    )


def _parent_evidence(detection: Mapping[str, str], rows: list[dict]):
    guid = detection.get("ParentProcessGuid")
    when = _timestamp(detection["UtcTime"])
    for row in rows:
        if (str(row.get("host", "")).casefold() != str(detection["host"]).casefold()
                or str(row.get("EventID")) != "1"
                or str(row.get("ProcessGuid", "")).casefold() != str(guid or "").casefold()):
            continue
        try:
            started = _timestamp(row["UtcTime"])
            # A parent's creation must precede the child's (a small clock tolerance).
            if started > when + timedelta(seconds=2):
                continue
            eid = f"sysmon:{row['host']}:{row['ProcessGuid']}"
            source = f"splunk:winlab:{row['host']}:{row['ProcessGuid']}"
            return normalize_sysmon_process_create(row, evidence_id=eid, source_ref=source)
        except (KeyError, ValueError, TypeError):
            continue
    return None


def _script_evidence(detection: Mapping[str, str], rows: list[dict]):
    """Use event host/PID/time and only claim completeness for full fragment sets."""
    host = str(detection["host"])
    pid = str(detection.get("ProcessId") or "")
    started = _timestamp(detection["UtcTime"])
    low = started - timedelta(seconds=SCRIPT_WINDOW_BEFORE_SECONDS)
    high = started + timedelta(seconds=SCRIPT_WINDOW_AFTER_SECONDS)
    evidence = []
    fragments: dict[str, dict] = {}
    seen: set[str] = set()

    for row in rows:
        if str(row.get("host", "")).casefold() != host.casefold() or str(row.get("ps_pid")) != pid:
            continue
        try:
            time_value = _timestamp(row["system_time"])
            if not low <= time_value <= high:
                continue
            sbid = str(row["ScriptBlockId"])
            nr = int(row["MessageNumber"])
            total = int(row["MessageTotal"])
            if not sbid or not 1 <= nr <= total or total > 100:
                continue
            record_id = str(row.get("record_id") or f"{sbid}:{nr}")
            event_id = f"ps4104:{host}:{record_id}"
            if event_id in seen:
                continue
            data = {
                "ScriptBlockId": sbid,
                "MessageNumber": str(nr),
                "MessageTotal": str(total),
                "ScriptBlockText": html.unescape(str(row["ScriptBlockText"])),
            }
            source = f"splunk:winlab:{host}:powershell4104:{record_id}"
            ev = normalize_powershell_script_block(
                data, system_time=time_value.isoformat(), evidence_id=event_id, source_ref=source
            )
            evidence.append(ev)
            seen.add(event_id)
            group = fragments.setdefault(sbid, {"total": total, "parts": set()})
            if group["total"] == total:
                group["parts"].add(nr)
            else:
                # Conflicting MessageTotal => do not call the evidence complete.
                group["total"] = -1
        except (KeyError, ValueError, TypeError):
            continue

    complete = any(
        group["total"] > 0 and group["parts"] == set(range(1, group["total"] + 1))
        for group in fragments.values()
    )
    return evidence, complete


def correlate_detection(detection: Mapping[str, str], parent_rows: list[dict], script_rows: list[dict]) -> AlertEnvelope:
    """Preserve all source refs and report missing evidence explicitly."""
    envelope = build_alert_envelope(detection)
    payload = envelope.model_dump(mode="json")
    parent = _parent_evidence(detection, parent_rows)
    if parent is not None and parent.id not in {e["id"] for e in payload["evidence"]}:
        payload["evidence"].append(parent.model_dump(mode="json"))
        payload["alert"]["event_refs"].append(parent.source_ref)
        payload["missing_evidence"].remove("parent_process_event")
    scripts, complete = _script_evidence(detection, script_rows)
    for evidence in scripts:
        payload["evidence"].append(evidence.model_dump(mode="json"))
        payload["alert"]["event_refs"].append(evidence.source_ref)
    if complete:
        payload["missing_evidence"].remove("powershell_script_block")
    # True in the returned model ONLY if the evidence really matched.
    return AlertEnvelope.model_validate(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Correlate real Splunk Sysmon EID 1 with parent and PowerShell 4104")
    parser.add_argument("--host", default="192.168.1.25")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--ca-file", help="Trusted CA bundle for Splunk TLS")
    parser.add_argument("--insecure-lab", action="store_true", help="Disable TLS validation only on the private lab")
    args = parser.parse_args()
    if args.insecure_lab and args.ca_file:
        parser.error("Use either --ca-file or --insecure-lab")
    context = ssl._create_unverified_context() if args.insecure_lab else ssl.create_default_context(cafile=args.ca_file)
    password = getpass.getpass("Mot de passe Splunk (non affiché) : ")
    results = []
    try:
        detections = fetch_detections(args.host, args.user, password, context=context)
        for detection in detections:
            try:
                started = _timestamp(detection["UtcTime"])
                parent_query = parent_search_query(detection)
                script_query = script_search_query(detection)
                parent_rows = []
                script_rows = []
                if parent_query:
                    parent_rows = fetch_search(
                        args.host, args.user, password, context=context, query=parent_query,
                        earliest=str(int(started.timestamp()) - 7 * 86400),
                        latest=str(int(started.timestamp()) + 3),
                    )
                if script_query:
                    script_rows = fetch_search(
                        args.host, args.user, password, context=context, query=script_query,
                        earliest=str(int(started.timestamp()) - SCRIPT_WINDOW_BEFORE_SECONDS),
                        latest=str(int(started.timestamp()) + SCRIPT_WINDOW_AFTER_SECONDS + 1),
                    )
                envelope = correlate_detection(detection, parent_rows, script_rows)
                results.append({
                    "alert_envelope": envelope.model_dump(mode="json"),
                    "triage": build_triage_result(envelope.model_dump(mode="json")),
                })
            except (ValueError, KeyError, TypeError) as exc:
                print(f"Détection ignorée / non corrélable : {exc}", file=sys.stderr)
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Erreur lors de la lecture de Splunk : {exc}", file=sys.stderr)
        return 1
    print(json.dumps(results, ensure_ascii=False, indent=2))
    print(f"Alertes traitées : {len(results)}", file=sys.stderr)
    return 0 if results else 2


if __name__ == "__main__":
    raise SystemExit(main())
