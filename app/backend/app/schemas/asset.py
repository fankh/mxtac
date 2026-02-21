from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, Field, field_validator

from ..core.validators import validate_ip_address

AssetType = Literal["server", "workstation", "network", "cloud", "container"]
OsFamily = Literal["linux", "windows", "macos", "other"]

# Tags: max 50 items, each tag up to 64 chars
_TagList = Annotated[list[str], Field(max_length=50)]


def _validate_ip_list(ips: list[str]) -> list[str]:
    for ip in ips:
        validate_ip_address(ip)
    return ips


class AssetCreate(BaseModel):
    hostname: str = Field(..., max_length=255)
    ip_addresses: list[str] = []
    os: str | None = Field(default=None, max_length=255)
    os_family: OsFamily | None = None
    asset_type: AssetType
    criticality: int = Field(default=3, ge=1, le=5)
    owner: str | None = Field(default=None, max_length=255)
    department: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=255)
    tags: list[str] = Field(default_factory=list, max_length=50)
    is_active: bool = True
    agent_id: str | None = Field(default=None, max_length=255)

    @field_validator("ip_addresses")
    @classmethod
    def validate_ip_addresses(cls, v: list[str]) -> list[str]:
        return _validate_ip_list(v)

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: list[str]) -> list[str]:
        for tag in v:
            if len(tag) > 64:
                raise ValueError(f"Tag exceeds 64 characters: {tag!r}")
        return v


class AssetUpdate(BaseModel):
    ip_addresses: list[str] | None = None
    os: str | None = Field(default=None, max_length=255)
    os_family: OsFamily | None = None
    asset_type: AssetType | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    owner: str | None = Field(default=None, max_length=255)
    department: str | None = Field(default=None, max_length=255)
    location: str | None = Field(default=None, max_length=255)
    tags: list[str] | None = Field(default=None, max_length=50)
    is_active: bool | None = None
    agent_id: str | None = Field(default=None, max_length=255)

    @field_validator("ip_addresses")
    @classmethod
    def validate_ip_addresses(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            return _validate_ip_list(v)
        return v

    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v: list[str] | None) -> list[str] | None:
        if v is not None:
            for tag in v:
                if len(tag) > 64:
                    raise ValueError(f"Tag exceeds 64 characters: {tag!r}")
        return v


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
