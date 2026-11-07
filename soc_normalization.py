from collections.abc import Mapping
from datetime import datetime, timezone

from soc_models import Evidence


def normalize_sysmon_process_create(
    fields: Mapping[str, str],
    *,
    evidence_id: str,
    source_ref: str,
) -> Evidence:
    timestamp = datetime.fromisoformat(fields["UtcTime"])
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return Evidence(
        id=evidence_id,
        type="sysmon_process_create",
        timestamp=timestamp,
        source_ref=source_ref,
        image=fields.get("Image"),
        command_line=fields.get("CommandLine"),
        parent_image=fields.get("ParentImage"),
        process_guid=fields.get("ProcessGuid"),
        parent_process_guid=fields.get("ParentProcessGuid"),
    )

def normalize_powershell_script_block(
    fields: Mapping[str, str],
    *,
    system_time: str,
    evidence_id: str,
    source_ref: str,
) -> Evidence:
    message_number = int(fields["MessageNumber"])
    message_total = int(fields["MessageTotal"])

    if not 1 <= message_number <= message_total:
        raise ValueError("Invalid PowerShell script block fragment position")

    return Evidence.model_validate(
        {
            "id": evidence_id,
            "type": "powershell_script_block",
            "timestamp": system_time,
            "source_ref": source_ref,
            "script_block_id": fields["ScriptBlockId"],
            "script_block_text": fields["ScriptBlockText"],
            "message_number": message_number,
            "message_total": message_total,
            "script_block_path": fields.get("Path") or None,
        }
    )