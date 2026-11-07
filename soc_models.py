from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    model_validator,
)


def to_utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc)


UtcTimestamp = Annotated[AwareDatetime, AfterValidator(to_utc)]
NonEmptyText = Annotated[str, Field(min_length=1)]


class SocModel(BaseModel):
    model_config = ConfigDict(extra="allow")


class Alert(SocModel):
    source: NonEmptyText
    instance_id: NonEmptyText
    alert_id: NonEmptyText
    rule_id: NonEmptyText
    rule_version: NonEmptyText
    timestamp: UtcTimestamp
    host_id: NonEmptyText
    event_refs: list[NonEmptyText]


class Evidence(SocModel):
    id: NonEmptyText
    type: NonEmptyText
    timestamp: UtcTimestamp
    source_ref: NonEmptyText
    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None


class AlertEnvelope(SocModel):
    schema_version: Literal["0.1"]
    synthetic: StrictBool
    alert: Alert
    evidence: list[Evidence]
    missing_evidence: list[NonEmptyText]

    @model_validator(mode="after")
    def check_unique_evidence_ids(self):
        evidence_ids = [event.id for event in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("Evidence IDs must be unique within the alert")
        return self