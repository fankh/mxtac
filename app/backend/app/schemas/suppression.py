"""Pydantic schemas for alert suppression rules (feature 9.11)."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

SeverityLevel = Literal["critical", "high", "medium", "low"]


class SuppressionRuleCreate(BaseModel):
    """Request body for POST /suppression-rules."""

    name: str = Field(..., min_length=1, max_length=255)
    reason: str | None = Field(default=None, max_length=1000)

    # Match fields — at least one must be provided
    rule_id: str | None = Field(default=None, max_length=255)
    host: str | None = Field(default=None, max_length=255)
    technique_id: str | None = Field(default=None, max_length=50)
    tactic: str | None = Field(default=None, max_length=100)
    severity: SeverityLevel | None = None

    is_active: bool = True
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def at_least_one_match_field(self) -> SuppressionRuleCreate:
        fields = (self.rule_id, self.host, self.technique_id, self.tactic, self.severity)
        if not any(f is not None for f in fields):
            raise ValueError(
                "At least one match field (rule_id, host, technique_id, tactic, severity) "
                "must be provided."
            )
        return self


class SuppressionRuleUpdate(BaseModel):
    """Request body for PATCH /suppression-rules/{id}."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    reason: str | None = Field(default=None, max_length=1000)

    rule_id: str | None = Field(default=None, max_length=255)
    host: str | None = Field(default=None, max_length=255)
    technique_id: str | None = Field(default=None, max_length=50)
    tactic: str | None = Field(default=None, max_length=100)
    severity: SeverityLevel | None = None

    is_active: bool | None = None
    expires_at: datetime | None = None


class SuppressionRule(BaseModel):
    """Response schema for a single suppression rule."""

    id: int
    name: str
    reason: str | None
    rule_id: str | None
    host: str | None
    technique_id: str | None
    tactic: str | None
    severity: str | None
    is_active: bool
    expires_at: datetime | None
    created_by: str
    hit_count: int
    last_hit_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
