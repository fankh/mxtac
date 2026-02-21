"""Pydantic schemas for Incident resources."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .detection import Detection as DetectionSchema

# Reuse same regex as auth.py — RFC 6762 compatible, allows .local domains
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", re.IGNORECASE)

SeverityLevel = Literal["critical", "high", "medium", "low"]
IncidentStatus = Literal["new", "investigating", "contained", "resolved", "closed"]
NoteType = Literal["comment", "status_change", "evidence"]


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=10000)
    severity: SeverityLevel
    detection_ids: list[str] = Field(default_factory=list, max_length=500)
    assigned_to: str | None = Field(default=None, max_length=254)

    @field_validator("assigned_to")
    @classmethod
    def validate_assigned_to_email(cls, v: str | None) -> str | None:
        if v is not None and not _EMAIL_RE.match(v):
            raise ValueError("assigned_to must be a valid email address")
        return v


class IncidentUpdate(BaseModel):
    """Partial update schema — only provided fields are changed."""

    title: str | None = Field(None, min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=10000)
    severity: SeverityLevel | None = None
    status: IncidentStatus | None = None
    priority: int | None = None
    assigned_to: str | None = Field(default=None, max_length=254)
    detection_ids: list[str] | None = Field(default=None, max_length=500)

    @field_validator("assigned_to")
    @classmethod
    def validate_assigned_to_email(cls, v: str | None) -> str | None:
        if v is not None and not _EMAIL_RE.match(v):
            raise ValueError("assigned_to must be a valid email address")
        return v


class NoteCreate(BaseModel):
    content: str = Field(..., min_length=1, max_length=5000)
    note_type: NoteType = "comment"


class IncidentNote(BaseModel):
    id: str
    author: str
    content: str
    note_type: NoteType = "comment"  # default preserves backward compat with existing notes
    created_at: datetime


class Incident(BaseModel):
    id: int
    title: str
    description: str | None
    severity: SeverityLevel
    status: str
    priority: int
    assigned_to: str | None
    created_by: str
    detection_ids: list[str]
    technique_ids: list[str]
    tactic_ids: list[str]
    hosts: list[str]
    ttd_seconds: int | None
    ttr_seconds: int | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class IncidentDetail(Incident):
    """Full incident detail including linked detections, notes, and computed duration."""

    detections: list[DetectionSchema]
    notes: list[IncidentNote]
    duration_seconds: int


class IncidentsByStatus(BaseModel):
    new: int = 0
    investigating: int = 0
    contained: int = 0
    resolved: int = 0
    closed: int = 0


class IncidentMetrics(BaseModel):
    """SLA metrics for incidents within a date range."""

    total_incidents: IncidentsByStatus
    mttr_seconds: float | None  # None when no closed incidents in range
    mttd_seconds: float | None  # None when no incidents with TTD data in range
    open_incidents_count: int
    incidents_by_severity: dict[str, int]
    incidents_this_week: int
    incidents_this_month: int
    from_date: datetime
    to_date: datetime
