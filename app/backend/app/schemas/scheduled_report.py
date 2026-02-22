"""Pydantic schemas for ScheduledReport API — feature 31.4."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

_VALID_TEMPLATE_TYPES = frozenset(
    [
        "executive_summary",
        "detection_report",
        "incident_report",
        "coverage_report",
        "compliance_summary",
    ]
)

_VALID_FORMATS = frozenset(["json", "csv"])


def _validate_cron(v: str) -> str:
    """Raise ValueError if *v* is not a valid 5-field cron expression."""
    try:
        from croniter import croniter  # noqa: PLC0415
    except ImportError as exc:
        raise ValueError("croniter package is required for cron validation") from exc

    if not croniter.is_valid(v):
        raise ValueError(
            f"{v!r} is not a valid cron expression. "
            "Use 5-field standard cron syntax, e.g. '0 8 * * 1'."
        )
    return v


class ScheduledReportCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    template_type: Literal[
        "executive_summary",
        "detection_report",
        "incident_report",
        "coverage_report",
        "compliance_summary",
    ]
    schedule: str = Field(
        ...,
        description="5-field cron expression (UTC), e.g. '0 8 * * 1' for weekly Monday 8am.",
    )
    params_json: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Template-specific params. Supported keys: "
            "``period_days`` (int, default 7) — look-back window; "
            "``framework`` (str) — for compliance_summary."
        ),
    )
    format: Literal["json", "csv"] = "json"
    enabled: bool = True
    notification_channel_id: int | None = None

    @field_validator("schedule")
    @classmethod
    def validate_schedule(cls, v: str) -> str:
        return _validate_cron(v)


class ScheduledReportUpdate(BaseModel):
    """All fields are optional — only supplied fields are updated."""

    name: str | None = Field(None, min_length=1, max_length=255)
    schedule: str | None = None
    params_json: dict[str, Any] | None = None
    format: Literal["json", "csv"] | None = None
    enabled: bool | None = None
    notification_channel_id: int | None = None
    # Explicitly pass null to clear the notification channel
    clear_notification_channel: bool = False

    @field_validator("schedule")
    @classmethod
    def validate_schedule(cls, v: str | None) -> str | None:
        if v is None:
            return v
        return _validate_cron(v)


class ScheduledReportResponse(BaseModel):
    id: str
    name: str
    template_type: str
    schedule: str
    params_json: dict[str, Any]
    format: str
    enabled: bool
    notification_channel_id: int | None
    last_run_at: datetime | None
    next_run_at: datetime | None
    created_by: str
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
