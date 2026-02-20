"""Pydantic schemas for Incident resources."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from .detection import Detection as DetectionSchema

SeverityLevel = Literal["critical", "high", "medium", "low"]
IncidentStatus = Literal["new", "investigating", "contained", "resolved", "closed"]


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    description: str | None = None
    severity: SeverityLevel
    detection_ids: list[str] = Field(default_factory=list)
    assigned_to: str | None = None


class IncidentUpdate(BaseModel):
    """Partial update schema — only provided fields are changed."""

    title: str | None = Field(None, min_length=1, max_length=500)
    description: str | None = None
    severity: SeverityLevel | None = None
    status: IncidentStatus | None = None
    priority: int | None = None
    assigned_to: str | None = None
    detection_ids: list[str] | None = None


class IncidentNote(BaseModel):
    id: str
    author: str
    content: str
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
