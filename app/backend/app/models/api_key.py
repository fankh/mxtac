from datetime import datetime
from hashlib import sha256

from sqlalchemy import Boolean, DateTime, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class APIKey(Base, TimestampMixin):
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Feature 1.11 — Scoped API keys
    # owner_id: UUID of the User who created this key (nullable for pre-1.11 keys)
    owner_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    # scopes: list of permission strings (None = unrestricted, for backward compat)
    scopes: Mapped[list | None] = mapped_column(JSON, nullable=True, default=None)
    # expires_at: optional expiry; None means the key never expires
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    # last_used_at: updated on every successful auth via X-API-Key
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )

    # Feature 3.9 — Permission sets
    # permission_set_id: UUID of the PermissionSet used at key creation (audit/display only)
    # The effective scopes are always stored in the `scopes` field (snapshotted at creation)
    permission_set_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<APIKey {self.id} label={self.label!r}>"


def hash_api_key(raw_key: str) -> str:
    return sha256(raw_key.encode()).hexdigest()
