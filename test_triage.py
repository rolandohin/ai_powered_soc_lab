import base64
import binascii
import unittest

from detection_rules import detect_powershell_signals
from triage import build_triage_result, decode_powershell_payload


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


class TestTriageIntegration(unittest.TestCase):
    def _triage_event(self, alert_id, image, command_line):
        data = {
            "alert": {"alert_id": alert_id},
            "evidence": [
                {
                    "id": "ev-001",
                    "image": image,
                    "command_line": command_line,
                }
            ],
            "missing_evidence": ["powershell_script_block"],
        }

        result = build_triage_result(data)
        self.assertEqual(result["missing_evidence"], ["powershell_script_block"])
        return result["evidence"][0]

    def test_keeps_detection_signal_when_decoding_fails(self):
        event = self._triage_event(
            "lab-invalid",
            "powershell.exe",
            "powershell.exe -EncodedCommand INVALID!",
        )

        self.assertEqual(event["signals"], ["powershell_encoded_command"])
        self.assertEqual(event["decode_status"], "failed")
        self.assertIsNone(event["decoded_command"])

    def test_detects_and_decodes_pwsh_ec_alias(self):
        payload = "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFMATwBDAC0ATABBAEIAJwA="
        event = self._triage_event(
            "lab-001",
            "pwsh.exe",
            f"pwsh.exe -ec {payload}",
            )
        
        self.assertEqual(event["signals"], ["powershell_encoded_command"])
        self.assertEqual(event["decode_status"], "decoded")
        self.assertEqual(event["decoded_command"], "Write-Output 'SOC-LAB'")

    def test_keeps_detection_signal_when_pwsh_e_payload_is_invalid(self):
        event = self._triage_event(
            "lab-invalid-e",
            "pwsh.exe",
            "pwsh.exe -e INVALID!",
        )

        self.assertEqual(event["signals"], ["powershell_encoded_command"])
        self.assertEqual(event["decode_status"], "failed")
        self.assertIsNone(event["decoded_command"])

    def test_does_not_match_pwsh_execution_policy(self):
        event = self._triage_event(
            "lab-execution-policy",
            "pwsh.exe",
            "pwsh.exe -ExecutionPolicy RemoteSigned",
        )

        self.assertEqual(event["signals"], [])
        self.assertEqual(event["decode_status"], "not_present")
        self.assertIsNone(event["decoded_command"])