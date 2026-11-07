import unittest
import json
from pathlib import Path

from soc_models import AlertEnvelope
from triage import build_triage_result

from soc_normalization import (
    normalize_powershell_script_block,
    normalize_sysmon_process_create,
)


class TestSysmonNormalization(unittest.TestCase):
    def test_normalizes_process_creation_and_preserves_provenance(self):
        fields = {
            "UtcTime": "2026-11-06 15:00:00.000",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -NoProfile",
            "ParentImage": r"C:\Windows\explorer.exe",
            "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
            "ParentProcessGuid": "{22222222-2222-2222-2222-222222222222}",
        }

        evidence = normalize_sysmon_process_create(
            fields,
            evidence_id="ev-001",
            source_ref="synthetic:sysmon:001",
        ).model_dump(mode="json")

        self.assertEqual(evidence["id"], "ev-001")
        self.assertEqual(evidence["type"], "sysmon_process_create")
        self.assertEqual(evidence["timestamp"], "2026-11-06T15:00:00Z")
        self.assertEqual(evidence["source_ref"], "synthetic:sysmon:001")
        self.assertEqual(evidence["image"], fields["Image"])
        self.assertEqual(evidence["command_line"], fields["CommandLine"])
        self.assertEqual(evidence["parent_image"], fields["ParentImage"])
        self.assertEqual(evidence["process_guid"], fields["ProcessGuid"])
        self.assertEqual(evidence["parent_process_guid"], fields["ParentProcessGuid"])


class TestPowerShellNormalization(unittest.TestCase):
    def test_preserves_script_block_fragment_and_provenance(self):
        fields = {
            "ScriptBlockId": "33333333-3333-3333-3333-333333333333",
            "ScriptBlockText": "\nWrite-Output 'SOC-LAB'\n",
            "MessageNumber": "2",
            "MessageTotal": "3",
            "Path": "",
        }

        evidence = normalize_powershell_script_block(
            fields,
            system_time="2026-11-06T15:00:01Z",
            evidence_id="ev-002",
            source_ref="synthetic:powershell:4104:002",
        ).model_dump(mode="json")

        self.assertEqual(evidence["id"], "ev-002")
        self.assertEqual(evidence["type"], "powershell_script_block")
        self.assertEqual(evidence["timestamp"], "2026-11-06T15:00:01Z")
        self.assertEqual(evidence["source_ref"], "synthetic:powershell:4104:002")
        self.assertEqual(evidence["script_block_id"], fields["ScriptBlockId"])
        self.assertEqual(evidence["script_block_text"], fields["ScriptBlockText"])
        self.assertEqual(evidence["message_number"], 2)
        self.assertEqual(evidence["message_total"], 3)
        self.assertIsNone(evidence["script_block_path"])

class TestMultiSourceTriage(unittest.TestCase):
    def test_triages_sysmon_and_powershell_evidence_in_one_alert(self):
        fixture = Path(__file__).resolve().parent / "fixtures" / "alert.json"
        data = json.loads(fixture.read_text(encoding="utf-8-sig"))
        original_event = data["evidence"][0]

        sysmon = normalize_sysmon_process_create(
            {
                "UtcTime": "2026-11-06 15:00:00.000",
                "Image": original_event["image"],
                "CommandLine": original_event["command_line"],
            },
            evidence_id="ev-001",
            source_ref="synthetic:sysmon:001",
        )

        script_block = normalize_powershell_script_block(
            {
                "ScriptBlockId": "33333333-3333-3333-3333-333333333333",
                "ScriptBlockText": "Write-Output 'SOC-LAB'",
                "MessageNumber": "1",
                "MessageTotal": "1",
            },
            system_time="2026-11-06T15:00:01Z",
            evidence_id="ev-002",
            source_ref="synthetic:powershell:4104:002",
        )

        data["evidence"] = [sysmon, script_block]
        data["missing_evidence"].remove("powershell_script_block")

        envelope = AlertEnvelope.model_validate(data)
        result = build_triage_result(envelope.model_dump(mode="json"))
        process_event, script_event = result["evidence"]

        self.assertEqual(result["alert"]["event_refs"], ["ev-001"])
        self.assertEqual(result["missing_evidence"], ["parent_process_event"])

        self.assertEqual(process_event["source_ref"], "synthetic:sysmon:001")
        self.assertEqual(process_event["signals"], ["powershell_encoded_command"])
        self.assertEqual(process_event["decoded_command"], "Write-Output 'SOC-LAB'")

        self.assertEqual(script_event["source_ref"], "synthetic:powershell:4104:002")
        self.assertEqual(script_event["script_block_text"], "Write-Output 'SOC-LAB'")
        self.assertEqual(script_event["signals"], [])
        self.assertEqual(script_event["decode_status"], "not_present")