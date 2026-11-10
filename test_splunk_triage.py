"""Offline contract tests: no live Splunk connection, no real credentials."""

import base64
import unittest

from splunk_triage import build_alert_envelope
from triage import build_triage_result


class TestLiveSplunkBridge(unittest.TestCase):
    def setUp(self):
        encoded = base64.b64encode("Write-Output 'SOC-LAB'".encode("utf-16-le")).decode("ascii")
        self.event = {
            "host": "WIN-LAB",
            "EventID": "1",
            "UtcTime": "2026-11-10 12:00:02.648",
            "ProcessGuid": "{62269ac2-0742-6af3-180a-000000000500}",
            "ParentProcessGuid": "{62269ac2-fec2-6af2-a506-000000000500}",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "powershell.exe -NoProfile -EncodedCommand " + encoded,
        }

    def test_real_envelope_and_decode(self):
        envelope = build_alert_envelope(self.event)
        self.assertFalse(envelope.synthetic)
        self.assertEqual(envelope.schema_version, "0.1")
        self.assertEqual(envelope.alert.rule_id, "powershell_encoded_command")
        self.assertEqual(len(envelope.evidence), 1)
        self.assertEqual(envelope.evidence[0].timestamp.isoformat(), "2026-11-10T12:00:02.648000+00:00")
        self.assertEqual(envelope.evidence[0].source_ref, envelope.alert.event_refs[0])
        triage = build_triage_result(envelope.model_dump(mode="json"))
        self.assertEqual(triage["evidence"][0]["decode_status"], "decoded")
        self.assertEqual(triage["evidence"][0]["decoded_command"], "Write-Output 'SOC-LAB'")
        self.assertEqual(triage["evidence"][0]["signals"], ["powershell_encoded_command"])

    def test_missing_required_field_rejected(self):
        self.event.pop("UtcTime")
        with self.assertRaisesRegex(ValueError, "UtcTime"):
            build_alert_envelope(self.event)

    def test_unrelated_process_rejected(self):
        self.event["Image"] = r"C:\Windows\System32\notepad.exe"
        with self.assertRaisesRegex(ValueError, "does not match"):
            build_alert_envelope(self.event)

    def test_other_event_id_rejected(self):
        self.event["EventID"] = "3"
        with self.assertRaisesRegex(ValueError, "Event ID 1"):
            build_alert_envelope(self.event)


if __name__ == "__main__":
    unittest.main()
