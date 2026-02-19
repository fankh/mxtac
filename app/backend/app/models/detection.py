from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class Detection(Base, TimestampMixin):
    __tablename__ = "detections"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)

    # ATT&CK
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    tactic_id: Mapped[str] = mapped_column(String(20), nullable=True)

    # Alert
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="active", index=True)
    priority: Mapped[str] = mapped_column(String(20), nullable=True)

    # Host / identity
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    user: Mapped[str] = mapped_column(String(255), nullable=True)
    process: Mapped[str] = mapped_column(String(500), nullable=True)

    # Source
    log_source: Mapped[str] = mapped_column(String(100), nullable=True)
    event_id: Mapped[str] = mapped_column(String(50), nullable=True)
    rule_name: Mapped[str] = mapped_column(String(500), nullable=True)

    # Metrics
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    cvss_v3: Mapped[float] = mapped_column(Float, nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, nullable=True)

    # Assignment
    assigned_to: Mapped[str] = mapped_column(String(255), nullable=True)

    # Event time (when the threat occurred, vs created_at = when detected)
    time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    def __repr__(self) -> str:
        return f"<Detection {self.id} {self.severity} {self.technique_id}>"
