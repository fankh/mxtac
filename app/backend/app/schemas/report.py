"""Pydantic schemas for report generation API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

_VALID_TEMPLATES = (
    "executive_summary",
    "detection_report",
    "incident_report",
    "coverage_report",
    "compliance_summary",
)


class ReportGenerateRequest(BaseModel):
    template_type: Literal[
        "executive_summary",
        "detection_report",
        "incident_report",
        "coverage_report",
        "compliance_summary",
    ]
    from_date: datetime
    to_date: datetime
    format: Literal["json", "csv"] = "json"
    # Optional extra params forwarded to the template (e.g. framework for compliance_summary)
    extra_params: dict[str, Any] | None = Field(default=None)

    @model_validator(mode="after")
    def _validate_date_range(self) -> "ReportGenerateRequest":
        if self.from_date > self.to_date:
            raise ValueError("from_date must not be after to_date")
        return self


class ReportGenerateResponse(BaseModel):
    report_id: str
    status: Literal["generating"] = "generating"


class ReportSummary(BaseModel):
    id: str
    template_type: str
    status: Literal["generating", "ready", "failed"]
    format: str
    created_by: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ReportDetail(ReportSummary):
    params_json: dict[str, Any]
    error: str | None = None
