from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

IOCType = Literal["ip", "domain", "hash_md5", "hash_sha256", "url", "email"]
SeverityLevel = Literal["critical", "high", "medium", "low"]


class IOCCreate(BaseModel):
    ioc_type: IOCType
    value: str = Field(..., max_length=2048)
    source: str = Field(..., max_length=64)
    confidence: int = Field(default=50, ge=0, le=100)
    severity: SeverityLevel
    description: str | None = None
    tags: list[str] = []
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None = None
    is_active: bool = True


class IOCUpdate(BaseModel):
    confidence: int | None = Field(default=None, ge=0, le=100)
    severity: SeverityLevel | None = None
    description: str | None = None
    tags: list[str] | None = None
    last_seen: datetime | None = None
    expires_at: datetime | None = None
    is_active: bool | None = None


class IOCResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    ioc_type: str
    value: str
    source: str
    confidence: int
    severity: str
    description: str | None
    tags: list
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    is_active: bool
    hit_count: int
    last_hit_at: datetime | None
    created_at: datetime
    updated_at: datetime


class IOCLookupRequest(BaseModel):
    ioc_type: IOCType
    value: str


class BulkImportResult(BaseModel):
    created: int
    skipped: int


class IOCStats(BaseModel):
    total: int
    by_type: dict[str, int]
    by_source: dict[str, int]
    active: int
    expired: int
