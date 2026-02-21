from pydantic import BaseModel, Field
from typing import Literal
from datetime import datetime

SeverityLevel = Literal["critical", "high", "medium", "low"]
DetectionStatus = Literal["active", "investigating", "resolved", "false_positive"]


class Detection(BaseModel):
    id: str
    score: float
    severity: SeverityLevel
    technique_id: str
    technique_name: str
    name: str
    host: str
    tactic: str
    status: DetectionStatus
    time: datetime
    # detail fields (returned in single-detection endpoint)
    user: str | None = None
    process: str | None = None
    rule_name: str | None = None
    log_source: str | None = None
    event_id: str | None = None
    occurrence_count: int | None = None
    description: str | None = None
    cvss_v3: float | None = None
    confidence: int | None = None
    tactic_id: str | None = None
    related_technique_ids: list[str] = []
    assigned_to: str | None = None
    priority: str | None = None


class DetectionUpdate(BaseModel):
    status: DetectionStatus | None = None
    assigned_to: str | None = Field(default=None, max_length=255)
    priority: str | None = Field(default=None, max_length=20)


class BulkStatusUpdate(BaseModel):
    ids: list[str] = Field(..., min_length=1, max_length=500)
    status: DetectionStatus


class BulkUpdateResult(BaseModel):
    updated: int
    not_found: list[str]
