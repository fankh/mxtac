from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from ..core.validators import validate_ip_address, validate_hostname

IOCType = Literal["ip", "domain", "hash_md5", "hash_sha256", "url", "email"]
SeverityLevel = Literal["critical", "high", "medium", "low"]

# Pre-compiled patterns for hash and email validation
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", re.IGNORECASE)


class IOCCreate(BaseModel):
    ioc_type: IOCType
    value: str = Field(..., max_length=2048)
    source: str = Field(..., max_length=64)
    confidence: int = Field(default=50, ge=0, le=100)
    severity: SeverityLevel
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=50)
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None = None
    is_active: bool = True

    @model_validator(mode="after")
    def validate_value_by_type(self) -> "IOCCreate":
        """Validate that value matches the declared ioc_type format."""
        ioc_type = self.ioc_type
        value = self.value
        if ioc_type == "ip":
            try:
                validate_ip_address(value)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
        elif ioc_type == "domain":
            try:
                validate_hostname(value)
            except ValueError as exc:
                raise ValueError(str(exc)) from exc
        elif ioc_type == "hash_md5":
            if not _MD5_RE.match(value):
                raise ValueError(f"Invalid MD5 hash (must be 32 hex characters): {value!r}")
        elif ioc_type == "hash_sha256":
            if not _SHA256_RE.match(value):
                raise ValueError(f"Invalid SHA-256 hash (must be 64 hex characters): {value!r}")
        elif ioc_type == "url":
            if not (value.startswith("http://") or value.startswith("https://")):
                raise ValueError("URL must start with http:// or https://")
        elif ioc_type == "email":
            if not _EMAIL_RE.match(value):
                raise ValueError(f"Invalid email address: {value!r}")
        return self


class IOCUpdate(BaseModel):
    confidence: int | None = Field(default=None, ge=0, le=100)
    severity: SeverityLevel | None = None
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] | None = Field(default=None, max_length=50)
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
    value: str = Field(..., max_length=2048)


class BulkImportResult(BaseModel):
    created: int
    skipped: int


class IOCStats(BaseModel):
    total: int
    by_type: dict[str, int]
    by_source: dict[str, int]
    active: int
    expired: int
