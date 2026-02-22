"""Pydantic schemas for Permission Sets (Feature 3.9)."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from ..core.rbac import PERMISSIONS

_VALID_SCOPES: frozenset[str] = frozenset(PERMISSIONS.keys())


def _validate_permissions(v: list[str]) -> list[str]:
    if not v:
        raise ValueError("permissions list must not be empty")
    invalid = [p for p in v if p not in _VALID_SCOPES]
    if invalid:
        raise ValueError(f"Invalid permission(s): {', '.join(sorted(invalid))}")
    return list(dict.fromkeys(v))  # deduplicate preserving order


class PermissionSetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1000)
    permissions: list[str] = Field(..., min_length=1)

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v: list[str]) -> list[str]:
        return _validate_permissions(v)


class PermissionSetUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=1000)
    permissions: list[str] | None = Field(None, min_length=1)

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        return _validate_permissions(v)


class PermissionSetResponse(BaseModel):
    id: str
    name: str
    description: str | None
    permissions: list[str]
    is_active: bool
    created_by: str
    created_at: datetime
    updated_at: datetime
