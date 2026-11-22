"""Sanitize Windows event XML fixtures so they can be committed and reused.

A fixture exported from a real lab machine (Event Viewer or Splunk ``_raw``)
contains identifiers of that machine: computer name, user names, domain SIDs,
user profile paths and IP addresses. This module replaces them with stable
placeholders while keeping everything detection and correlation tests need:
event structure, EventID, Image, CommandLine, Hashes, ProcessGuid and
ParentProcessGuid.

Nothing in the event is executed. The input file is never modified.

Usage:
    python sanitize_fixture.py RAW.xml -o fixtures/sysmon-event-1.xml
    python sanitize_fixture.py --check fixtures/*.xml
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"e": EVENT_NS}

PLACEHOLDER_COMPUTER = "WIN-LAB"
PLACEHOLDER_USER = "labuser"
PLACEHOLDER_SID = "S-1-5-21-1000000000-2000000000-3000000000-1001"
PLACEHOLDER_IP_PREFIX = "192.0.2."  # TEST-NET-1 (RFC 5737), reserved for documentation

BUILTIN_ACCOUNT_PREFIXES = ("NT AUTHORITY\\", "NT SERVICE\\", "WINDOW MANAGER\\", "FONT DRIVER HOST\\")
BUILTIN_PROFILES = {"public", "default", "all users", PLACEHOLDER_USER}

DOMAIN_SID_RE = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+")
PROFILE_PATH_RE = re.compile(r"(?i)(C:\\Users\\)([^\\\"\s]+)")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
SAFE_IPS = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
MIN_IDENTIFIER_LENGTH = 3


def _data_fields(root: ET.Element, name: str) -> list[ET.Element]:
    return root.findall(f".//e:EventData/e:Data[@Name='{name}']", NS)


def collect_identifiers(root: ET.Element, extra_terms: list[str] | None = None) -> dict[str, str]:
    """Map each real identifier found in the event to its placeholder."""
    identifiers: dict[str, str] = {}

    for computer in root.findall(".//e:System/e:Computer", NS):
        fqdn = (computer.text or "").strip()
        if fqdn:
            identifiers[fqdn] = PLACEHOLDER_COMPUTER
            identifiers[fqdn.split(".")[0]] = PLACEHOLDER_COMPUTER

    for field in _data_fields(root, "User"):
        account = (field.text or "").strip()
        if not account or account.upper().startswith(BUILTIN_ACCOUNT_PREFIXES):
            continue
        domain, _, user = account.rpartition("\\")
        identifiers[user] = PLACEHOLDER_USER
        if domain:
            identifiers[domain] = PLACEHOLDER_COMPUTER

    for element in root.iter():
        for match in PROFILE_PATH_RE.finditer(element.text or ""):
            if match.group(2).casefold() not in BUILTIN_PROFILES:
                identifiers[match.group(2)] = PLACEHOLDER_USER

    for term in extra_terms or []:
        identifiers[term] = PLACEHOLDER_USER

    # Never replace placeholders or tiny strings that would corrupt the event.
    return {
        real: placeholder
        for real, placeholder in identifiers.items()
        if len(real) >= MIN_IDENTIFIER_LENGTH and real.casefold() != placeholder.casefold()
    }


def scrub_text(text: str, identifiers: dict[str, str], ip_map: dict[str, str]) -> str:
    """Replace SIDs, IPs and known identifiers inside one string."""
    text = DOMAIN_SID_RE.sub(PLACEHOLDER_SID, text)

    def replace_ip(match: re.Match[str]) -> str:
        ip = match.group(0)
        if ip in SAFE_IPS or ip.startswith(PLACEHOLDER_IP_PREFIX):
            return ip
        ip_map.setdefault(ip, f"{PLACEHOLDER_IP_PREFIX}{len(ip_map) + 10}")
        return ip_map[ip]

    text = IPV4_RE.sub(replace_ip, text)

    # Longest first so "DESKTOP-1.corp.example" is replaced before "DESKTOP-1".
    for real in sorted(identifiers, key=len, reverse=True):
        pattern = re.compile(rf"(?<![\w-]){re.escape(real)}(?![\w-])", re.IGNORECASE)
        text = pattern.sub(identifiers[real], text)
    return text


def sanitize_tree(root: ET.Element, extra_terms: list[str] | None = None) -> ET.Element:
    """Sanitize every text node and attribute of the event in place."""
    identifiers = collect_identifiers(root, extra_terms)
    ip_map: dict[str, str] = {}
    for element in root.iter():
        if element.text:
            element.text = scrub_text(element.text, identifiers, ip_map)
        for key, value in element.attrib.items():
            element.attrib[key] = scrub_text(value, identifiers, ip_map)
    return root


def find_leaks(root: ET.Element) -> list[str]:
    """Return human-readable findings; an empty list means the fixture is clean."""
    findings: list[str] = []

    for computer in root.findall(".//e:System/e:Computer", NS):
        if (computer.text or "").strip() != PLACEHOLDER_COMPUTER:
            findings.append("System/Computer is not the placeholder")

    for field in _data_fields(root, "User"):
        account = (field.text or "").strip()
        expected = f"{PLACEHOLDER_COMPUTER}\\{PLACEHOLDER_USER}"
        if account and account != expected and not account.upper().startswith(BUILTIN_ACCOUNT_PREFIXES):
            findings.append("EventData/User is a real account")

    for element in root.iter():
        values = [element.text or "", *element.attrib.values()]
        for value in values:
            if any(sid != PLACEHOLDER_SID for sid in DOMAIN_SID_RE.findall(value)):
                findings.append("domain SID found")
            for match in PROFILE_PATH_RE.finditer(value):
                if match.group(2).casefold() not in BUILTIN_PROFILES:
                    findings.append("user profile path found")
            for ip in IPV4_RE.findall(value):
                if ip not in SAFE_IPS and not ip.startswith(PLACEHOLDER_IP_PREFIX):
                    findings.append("IPv4 address found")

    return sorted(set(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sanitize Windows event XML fixtures")
    parser.add_argument("paths", nargs="+", type=Path, help="raw XML to sanitize, or fixtures to check")
    parser.add_argument("-o", "--output", type=Path, help="sanitized output file (must not exist)")
    parser.add_argument("--extra-term", action="append", default=[], help="extra string to replace")
    parser.add_argument("--check", action="store_true", help="only report leaks; exit 1 if any")
    args = parser.parse_args(argv)

    if args.check:
        dirty = False
        for path in args.paths:
            findings = find_leaks(ET.parse(path).getroot())
            print(f"{path}: {'OK' if not findings else 'LEAK: ' + '; '.join(findings)}")
            dirty = dirty or bool(findings)
        return 1 if dirty else 0

    if len(args.paths) != 1 or args.output is None:
        parser.error("sanitizing needs exactly one input file and --output")
    source, output = args.paths[0], args.output
    if output.exists():
        parser.error(f"{output} already exists; refusing to overwrite")

    ET.register_namespace("", EVENT_NS)
    tree = ET.parse(source)
    sanitize_tree(tree.getroot(), args.extra_term)
    findings = find_leaks(tree.getroot())
    if findings:
        print("Sanitized output still has leaks: " + "; ".join(findings), file=sys.stderr)
        return 1

    output.parent.mkdir(parents=True, exist_ok=True)
    tree.write(output, encoding="utf-8", xml_declaration=True)
    print(f"Sanitized fixture written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
