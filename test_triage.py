import base64
import binascii
import unittest

from triage import decode_powershell_payload
from detection_rules import detect_powershell_signals


class TestPowerShellDecoding(unittest.TestCase):
    def test_decodes_valid_payload(self):
        expected = "Write-Output 'SOC-LAB'"
        encoded = base64.b64encode(expected.encode("utf-16-le")).decode("ascii")
        self.assertEqual(decode_powershell_payload(encoded), expected)

    def test_rejects_invalid_base64(self):
        with self.assertRaises(binascii.Error):
            decode_powershell_payload("INVALID!")


class TestPowerShellDetection(unittest.TestCase):
    def test_detects_encoded_command_with_full_path_and_mixed_case(self):
        event = {
            "image": r"C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE",
            "command_line": "PowerShell.EXE -eNcOdEdCoMmAnD INVALID!",
        }

        self.assertEqual(
            detect_powershell_signals(event),
            ["powershell_encoded_command"],
        )

    def test_ignores_powershell_without_encoded_command(self):
        event = {
            "image": "powershell.exe",
            "command_line": "powershell.exe -NoProfile",
        }

        self.assertEqual(detect_powershell_signals(event), [])

    def test_ignores_non_powershell_executable(self):
        event = {
            "image": "tool.exe",
            "command_line": "tool.exe -EncodedCommand INVALID!",
        }

        self.assertEqual(detect_powershell_signals(event), [])