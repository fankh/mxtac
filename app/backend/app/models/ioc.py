from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class IOC(Base, TimestampMixin):
    """Indicator of Compromise — stores threat intelligence indicators."""

    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Indicator identity
    ioc_type: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )  # ip / domain / hash_md5 / hash_sha256 / url / email
    value: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)

    # Provenance
    source: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # e.g. "opencti", "manual", "stix-feed"

    # Risk assessment
    confidence: Mapped[int] = mapped_column(
        Integer, nullable=False, default=50, server_default="50"
    )  # 0-100
    severity: Mapped[str] = mapped_column(
        String(20), nullable=False
    )  # critical / high / medium / low

    # Metadata
    description: Mapped[str] = mapped_column(Text, nullable=True)
    tags: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list, server_default="[]"
    )  # e.g. ["apt28", "phishing"]

    # Lifecycle timestamps
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # State
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )

    # Match tracking
    hit_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    last_hit_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),
        Index("ix_iocs_type_value", "ioc_type", "value"),
    )

    def __repr__(self) -> str:
        return f"<IOC {self.id} [{self.ioc_type}] {self.value!r} ({self.severity})>"
