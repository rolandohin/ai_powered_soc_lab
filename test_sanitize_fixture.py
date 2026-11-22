import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from sanitize_fixture import (
    NS,
    PLACEHOLDER_SID,
    find_leaks,
    main,
    sanitize_tree,
)

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# Synthetic raw event: every identifier below is invented for the test.
RAW_EVENT = r"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1</EventID>
    <Computer>DESKTOP-JD42.corp.example</Computer>
    <Security UserID="S-1-5-21-111-222-333-1104"/>
  </System>
  <EventData>
    <Data Name="UtcTime">2026-11-10 09:15:02.123</Data>
    <Data Name="ProcessGuid">{11111111-2222-3333-4444-555555555555}</Data>
    <Data Name="ProcessId">4242</Data>
    <Data Name="Image">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
    <Data Name="CommandLine">powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAGgAaQAiAA== -WorkingDirectory C:\Users\jdoe\Desktop</Data>
    <Data Name="User">CORP\jdoe</Data>
    <Data Name="Hashes">SHA256=ABCDEF0123456789</Data>
    <Data Name="ParentProcessGuid">{66666666-7777-8888-9999-000000000000}</Data>
    <Data Name="ParentCommandLine">"C:\Windows\explorer.exe" /connect 10.20.30.40</Data>
  </EventData>
</Event>"""


def field(root: ET.Element, name: str) -> str:
    return root.find(f".//e:EventData/e:Data[@Name='{name}']", NS).text


def test_raw_event_is_reported_as_leaking():
    findings = find_leaks(ET.fromstring(RAW_EVENT))
    assert "System/Computer is not the placeholder" in findings
    assert "EventData/User is a real account" in findings
    assert "domain SID found" in findings
    assert "user profile path found" in findings
    assert "IPv4 address found" in findings


def test_sanitize_removes_identifiers_everywhere():
    root = sanitize_tree(ET.fromstring(RAW_EVENT))
    text = ET.tostring(root, encoding="unicode")

    for secret in ("jdoe", "DESKTOP-JD42", "corp.example", "CORP", "S-1-5-21-111", "10.20.30.40"):
        assert secret not in text
    assert find_leaks(root) == []
    assert root.find(".//e:Security", NS).get("UserID") == PLACEHOLDER_SID
    assert field(root, "User") == "WIN-LAB\\labuser"


def test_sanitize_keeps_detection_and_correlation_fields():
    root = sanitize_tree(ET.fromstring(RAW_EVENT))
    assert field(root, "ProcessGuid") == "{11111111-2222-3333-4444-555555555555}"
    assert field(root, "ParentProcessGuid") == "{66666666-7777-8888-9999-000000000000}"
    assert field(root, "ProcessId") == "4242"
    assert field(root, "Hashes") == "SHA256=ABCDEF0123456789"
    assert "-EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAGgAaQAiAA==" in field(root, "CommandLine")


def test_builtin_accounts_are_kept():
    raw = RAW_EVENT.replace("CORP\\jdoe", "NT AUTHORITY\\SYSTEM")
    root = sanitize_tree(ET.fromstring(raw))
    assert field(root, "User") == "NT AUTHORITY\\SYSTEM"


def test_cli_refuses_to_overwrite(tmp_path):
    source = tmp_path / "raw.xml"
    source.write_text(RAW_EVENT, encoding="utf-8")
    with pytest.raises(SystemExit):
        main([str(source), "-o", str(source)])


def test_cli_writes_clean_fixture(tmp_path):
    source = tmp_path / "raw.xml"
    output = tmp_path / "clean.xml"
    source.write_text(RAW_EVENT, encoding="utf-8")
    assert main([str(source), "-o", str(output)]) == 0
    assert main(["--check", str(output)]) == 0
    assert source.read_text(encoding="utf-8") == RAW_EVENT


@pytest.mark.parametrize("fixture", sorted(FIXTURES_DIR.glob("*.xml")), ids=lambda p: p.name)
def test_committed_xml_fixtures_are_sanitized(fixture):
    assert find_leaks(ET.parse(fixture).getroot()) == []
