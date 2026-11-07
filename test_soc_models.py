import json
import unittest
from pathlib import Path

from pydantic import ValidationError

from soc_models import AlertEnvelope


class TestAlertEnvelope(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parent / "fixtures" / "alert.json"
        self.alert_json = path.read_text(encoding="utf-8-sig")
        self.data = json.loads(self.alert_json)

    def test_accepts_original_alert_and_preserves_evidence(self):
        envelope = AlertEnvelope.model_validate_json(self.alert_json)

        self.assertEqual(envelope.alert.alert_id, "lab-001")
        self.assertEqual(envelope.alert.event_refs, ["ev-001"])
        self.assertEqual(envelope.evidence[0].source_ref, "synthetic:sysmon:001")
        self.assertIn("powershell_script_block", envelope.missing_evidence)

    def test_normalizes_timestamp_to_utc(self):
        self.data["alert"]["timestamp"] = "2026-11-06T16:00:00+01:00"

        result = AlertEnvelope.model_validate(self.data).model_dump(mode="json")

        self.assertEqual(result["alert"]["timestamp"], "2026-11-06T15:00:00Z")

    def test_rejects_timestamp_without_timezone(self):
        self.data["alert"]["timestamp"] = "2026-11-06T16:00:00"

        with self.assertRaises(ValidationError) as error:
            AlertEnvelope.model_validate(self.data)

        self.assertEqual(error.exception.errors()[0]["loc"], ("alert", "timestamp"))

    def test_rejects_duplicate_evidence_ids(self):
        self.data["evidence"].append(self.data["evidence"][0].copy())

        with self.assertRaisesRegex(ValidationError, "Evidence IDs must be unique"):
            AlertEnvelope.model_validate(self.data)

    def test_rejects_unsupported_schema_version(self):
        self.data["schema_version"] = "99.0"

        with self.assertRaises(ValidationError) as error:
            AlertEnvelope.model_validate(self.data)

        self.assertEqual(error.exception.errors()[0]["loc"], ("schema_version",))