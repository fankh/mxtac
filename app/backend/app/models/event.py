"""Event ORM model — stores normalized OCSF events in PostgreSQL."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:
    from sqlalchemy import Text as JSON  # type: ignore[assignment]

from .base import Base, TimestampMixin, new_uuid


class Event(Base, TimestampMixin):
    """Normalized OCSF security event stored in PostgreSQL.

    Key indexed columns are extracted from the full OCSF payload for efficient
    SQL filtering. The full payload is preserved in ``raw`` (JSON).
    """

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)

    # OCSF core identifiers
    event_uid: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    class_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    class_uid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)

    # Entity fields — extracted for fast WHERE-clause filtering
    src_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    username: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    process_hash: Mapped[str | None] = mapped_column(
        String(128), index=True, nullable=True
    )

    # Searchable free-text summary (concatenated from key description fields)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Source connector identifier (wazuh, zeek, suricata, …)
    source: Mapped[str | None] = mapped_column(String(32), index=True, nullable=True)

    # Full OCSF payload as JSON
    raw: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Event {self.id} class={self.class_name} sev={self.severity_id}>"
