from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

AssetType = Literal["server", "workstation", "network", "cloud", "container"]
OsFamily = Literal["linux", "windows", "macos", "other"]


class AssetCreate(BaseModel):
    hostname: str = Field(..., max_length=255)
    ip_addresses: list[str] = []
    os: str | None = Field(default=None, max_length=255)
    os_family: str | None = Field(default=None, max_length=32)
    asset_type: AssetType
    criticality: int = Field(default=3, ge=1, le=5)
    owner: str | None = Field(default=None, max_length=255)
    department: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=255)
    tags: list[str] = []
    is_active: bool = True
    agent_id: str | None = Field(default=None, max_length=255)


class AssetUpdate(BaseModel):
    ip_addresses: list[str] | None = None
    os: str | None = None
    os_family: str | None = None
    asset_type: AssetType | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    owner: str | None = None
    department: str | None = None
    location: str | None = None
    tags: list[str] | None = None
    is_active: bool | None = None
    agent_id: str | None = None


class AssetResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    hostname: str
    ip_addresses: list
    os: str | None
    os_family: str | None
    asset_type: str
    criticality: int
    owner: str | None
    department: str | None
    location: str | None
    tags: list
    is_active: bool
    last_seen_at: datetime | None
    agent_id: str | None
    detection_count: int
    incident_count: int
    created_at: datetime
    updated_at: datetime


class BulkAssetResult(BaseModel):
    created: int
    skipped: int


class AssetStats(BaseModel):
    total: int
    by_type: dict[str, int]
    by_criticality: dict[str, int]
    by_os_family: dict[str, int]
