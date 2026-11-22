"""Evasion corpus for detection_rules.py.

Each case is a command line the rule MUST detect (true positive) or MUST
ignore (false-positive trap). Adding a new evasion or a new false positive
found in the lab means adding one line to the matching list.
"""

import base64

import pytest

from detection_rules import ENCODED_COMMAND_NAMES, detect_powershell_signals, is_powershell
from triage import build_triage_result

SIGNAL = ["powershell_encoded_command"]
EN_DASH, EM_DASH, HORIZONTAL_BAR = "\u2013", "\u2014", "\u2015"

# Benign payload: Write-Output 'SOC-LAB', Base64 of UTF-16LE.
PAYLOAD = base64.b64encode("Write-Output 'SOC-LAB'".encode("utf-16-le")).decode("ascii")


def event(command_line: str, image: str = "powershell.exe", original_file_name: str | None = None) -> dict:
    return {"image": image, "command_line": command_line, "original_file_name": original_file_name}


# --- Must be detected -------------------------------------------------------

TRUE_POSITIVES = {
    "full name": "powershell.exe -EncodedCommand X",
    "alias e": "powershell.exe -e X",
    "alias ec": "powershell.exe -ec X",
    "prefix enc": "powershell.exe -enc X",
    "prefix encod": "powershell.exe -encod X",
    "prefix EncodedC mixed case": "powershell.exe -EncodedC X",
    "upper case": "POWERSHELL.EXE -ENC X",
    "after other options": "powershell.exe -NoP -NonI -W Hidden -enc X",
    "quoted parameter": 'powershell.exe "-enc" X',
    "slash prefix": "powershell.exe /enc X",
    "en dash": f"powershell.exe {EN_DASH}enc X",
    "em dash": f"powershell.exe {EM_DASH}enc X",
    "horizontal bar": f"powershell.exe {HORIZONTAL_BAR}enc X",
    "tab separator": "powershell.exe\t-enc\tX",
}


@pytest.mark.parametrize("command_line", TRUE_POSITIVES.values(), ids=TRUE_POSITIVES.keys())
def test_detects_encoded_command_variants(command_line):
    assert detect_powershell_signals(event(command_line)) == SIGNAL


# --- Must NOT be detected ---------------------------------------------------

FALSE_POSITIVE_TRAPS = {
    "ExecutionPolicy starts with e": "powershell.exe -ExecutionPolicy Bypass",
    "ep abbreviation": "powershell.exe -ep Bypass",
    "ErrorAction abbreviation": "powershell.exe -ea 0",
    "NoExit": "powershell.exe -NoExit",
    "longer than the full name": "powershell.exe -EncodedCommandX X",
    "enc inside a word": "powershell.exe -File C:\\lab\\test-enc.ps1",
    "no parameter at all": "powershell.exe Get-Date",
    "empty command line": "",
}


@pytest.mark.parametrize("command_line", FALSE_POSITIVE_TRAPS.values(), ids=FALSE_POSITIVE_TRAPS.keys())
def test_ignores_false_positive_traps(command_line):
    assert detect_powershell_signals(event(command_line)) == []


# --- Which process is PowerShell --------------------------------------------

def test_renamed_powershell_is_detected_through_original_file_name():
    renamed = event("notepad.exe -enc X", image=r"C:\Users\Public\notepad.exe", original_file_name="PowerShell.EXE")
    assert is_powershell(renamed)
    assert detect_powershell_signals(renamed) == SIGNAL


def test_renamed_pwsh_is_detected_through_original_file_name():
    renamed = event("update.exe -enc X", image=r"C:\Temp\update.exe", original_file_name="pwsh.dll")
    assert detect_powershell_signals(renamed) == SIGNAL


def test_other_program_with_same_option_is_ignored():
    other = event("tool.exe -enc X", image=r"C:\Tools\tool.exe", original_file_name="tool.exe")
    assert not is_powershell(other)
    assert detect_powershell_signals(other) == []


def test_missing_original_file_name_keeps_previous_behavior():
    assert detect_powershell_signals({"image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                                      "command_line": "powershell.exe -enc X"}) == SIGNAL
    assert detect_powershell_signals({"image": None, "command_line": None}) == []


# --- The generated name list -------------------------------------------------

def test_name_list_contains_every_prefix_and_the_ec_alias():
    assert len(ENCODED_COMMAND_NAMES) == 15
    assert ENCODED_COMMAND_NAMES[0] == "encodedcommand"
    assert {"e", "ec", "en", "enc"} <= set(ENCODED_COMMAND_NAMES)


# --- Integration with triage.py: the payload must still be captured ----------

@pytest.mark.parametrize("option", ["-enc", "/enc", f"{EN_DASH}enc", '"-EncodedC"'])
def test_triage_decodes_payload_for_new_variants(option):
    data = {
        "alert": {"alert_id": "lab-evasion"},
        "evidence": [{"id": "ev-1", "type": "sysmon_process_create", "image": "powershell.exe",
                      "command_line": f"powershell.exe -NoProfile {option} {PAYLOAD}"}],
        "missing_evidence": [],
    }
    result = build_triage_result(data)["evidence"][0]
    assert result["signals"] == SIGNAL
    assert result["decode_status"] == "decoded"
    assert result["decoded_command"] == "Write-Output 'SOC-LAB'"