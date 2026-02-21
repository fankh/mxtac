from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class Agent(Base, TimestampMixin):
    __tablename__ = "agents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    agent_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    # mxguard | mxwatch

    version: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")

    # Status: online | degraded | offline
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="offline", index=True)
    last_heartbeat: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Configuration stored as JSON string
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    def __repr__(self) -> str:
        return f"<Agent {self.hostname} type={self.agent_type} status={self.status}>"
