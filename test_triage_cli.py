import json
import sys

from triage import main


def test_cli_prints_json_report(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["triage.py", "--json"])

    main()

    report = json.loads(capsys.readouterr().out)
    event = report["evidence"][0]

    assert report["alert"]["alert_id"] == "lab-001"
    assert "powershell_encoded_command" in event["signals"]
    assert event["decode_status"] == "decoded"
    assert event["decoded_command"] == "Write-Output 'SOC-LAB'"
    assert "powershell_script_block" in report["missing_evidence"]


def test_cli_prints_human_readable_report(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["triage.py"])

    main()

    output = capsys.readouterr().out

    assert "lab-001" in output
    assert "Write-Output 'SOC-LAB'" in output
    assert "powershell_script_block" in output