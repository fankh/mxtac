from datetime import datetime

from sqlalchemy import DateTime, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class Incident(Base, TimestampMixin):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Triage
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="new", server_default="new", index=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=3, server_default="3")

    # Assignment
    assigned_to: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)

    # Linked entities (JSON arrays)
    detection_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list, server_default="[]")
    technique_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list, server_default="[]")
    tactic_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list, server_default="[]")
    hosts: Mapped[list] = mapped_column(JSON, nullable=False, default=list, server_default="[]")

    # Metrics
    ttd_seconds: Mapped[int] = mapped_column(Integer, nullable=True)
    ttr_seconds: Mapped[int] = mapped_column(Integer, nullable=True)

    # Timeline / notes (list of {id, author, content, created_at} dicts)
    notes: Mapped[list] = mapped_column(JSON, nullable=False, default=list, server_default="[]")

    # Lifecycle
    closed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<Incident {self.id} [{self.severity}] {self.title!r}>"
