"""Offline tests: no Splunk access, network, or real credentials required."""

import base64
import unittest
from datetime import datetime, timedelta, timezone
from soc_correlation import correlate_detection, parent_search_query, script_search_query
from triage import build_triage_result


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        cmd = base64.b64encode("Write-Output 'SOC-LAB'".encode("utf-16-le")).decode()
        self.child = {
            "host": "WIN-LAB", "EventID": "1", "UtcTime": "2026-11-10 12:00:02.648",
            "ProcessGuid": "{62269ac2-0742-6af3-180a-000000000500}",
            "ParentProcessGuid": "{62269ac2-fec2-6af2-a506-000000000500}",
            "ProcessId": "5160", "ParentProcessId": "1216",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "ParentImage": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "powershell.exe -EncodedCommand " + cmd,
        }
        self.parent = {
            "host": "WIN-LAB", "EventID": "1", "UtcTime": "2026-11-10 11:59:00.000",
            "ProcessGuid": self.child["ParentProcessGuid"], "ParentProcessGuid": "{00000000-0000-0000-0000-000000000000}",
            "Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "cmd.exe",
        }
        self.script = {
            "host": "WIN-LAB", "ps_pid": "5160", "system_time": "2026-11-10T12:00:03.000000Z",
            "record_id": "1000", "ScriptBlockId": "{script-id}", "ScriptBlockText": "Write-Output 'SOC-LAB'",
            "MessageNumber": "1", "MessageTotal": "1",
        }

    def test_full_correlation_and_decode(self):
        alert = correlate_detection(self.child, [self.parent], [self.script])
        self.assertFalse(alert.synthetic)
        self.assertEqual(alert.missing_evidence, [])
        self.assertEqual(len(alert.evidence), 3)
        self.assertEqual(len(alert.alert.event_refs), 3)
        types = {ev.type for ev in alert.evidence}
        self.assertEqual(types, {"sysmon_process_create", "powershell_script_block"})
        triage = build_triage_result(alert.model_dump(mode="json"))
        self.assertEqual(triage["evidence"][0]["decoded_command"], "Write-Output 'SOC-LAB'")

    def test_missing_parent_and_script_reported(self):
        alert = correlate_detection(self.child, [], [])
        self.assertEqual(alert.missing_evidence, ["parent_process_event", "powershell_script_block"])
        self.assertEqual(len(alert.evidence), 1)

    def test_wrong_parent_guid_rejected(self):
        self.parent["ProcessGuid"] = "{d1a4fbb3-1111-1111-1111-111111111111}"
        alert = correlate_detection(self.child, [self.parent], [self.script])
        self.assertIn("parent_process_event", alert.missing_evidence)
        self.assertNotIn("powershell_script_block", alert.missing_evidence)

    def test_wrong_pid_or_host_rejected(self):
        self.script["ps_pid"] = "9999"
        alert = correlate_detection(self.child, [self.parent], [self.script])
        self.assertIn("powershell_script_block", alert.missing_evidence)

    def test_outside_time_window_rejected(self):
        self.script["system_time"] = "2026-11-10T12:30:00Z"
        alert = correlate_detection(self.child, [self.parent], [self.script])
        self.assertIn("powershell_script_block", alert.missing_evidence)

    def test_fragmented_complete_script_block(self):
        self.script["ScriptBlockText"] = "Write-Output "
        self.script["MessageTotal"] = "2"
        second = {**self.script, "record_id": "1001", "MessageNumber": "2", "ScriptBlockText": "'SOC-LAB'"}
        alert = correlate_detection(self.child, [self.parent], [self.script, second])
        self.assertEqual(alert.missing_evidence, [])
        self.assertEqual(len(alert.evidence), 4)

    def test_missing_fragment_keeps_missing_evidence(self):
        self.script["MessageTotal"] = "2"
        alert = correlate_detection(self.child, [self.parent], [self.script])
        self.assertIn("powershell_script_block", alert.missing_evidence)
        self.assertEqual(len(alert.evidence), 3)

    def test_xml_encoded_script_text_decoded(self):
        self.script["ScriptBlockText"] = "Write-Output '&lt;SOC-LAB&gt;'"
        alert = correlate_detection(self.child, [], [self.script])
        self.assertEqual(alert.evidence[-1].model_dump()["script_block_text"], "Write-Output '<SOC-LAB>'")

    def test_queries_bounded_and_filtered(self):
        p = parent_search_query(self.child)
        s = script_search_query(self.child)
        self.assertIn("ParentProcessGuid", p)
        self.assertIn("ProcessGuid=", p)
        self.assertIn('ps_pid="5160"', s)
        self.assertIn('ps_event_id="4104"', s)
        self.assertIn("head 100", s)

    def test_unsafe_host_disallowed(self):
        self.child["host"] = 'WIN-LAB" | delete *'
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            parent_search_query(self.child)

    def test_missing_pid_does_not_claim_script(self):
        del self.child["ProcessId"]
        self.assertIsNone(script_search_query(self.child))
        alert = correlate_detection(self.child, [self.parent], [])
        self.assertIn("powershell_script_block", alert.missing_evidence)


if __name__ == "__main__":
    unittest.main()
