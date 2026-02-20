from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class Asset(Base, TimestampMixin):
    """CMDB-style asset inventory entry for tracked hosts and devices."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Identity
    hostname: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    ip_addresses: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list, server_default="[]"
    )  # e.g. ["10.0.1.5", "192.168.1.100"]

    # OS
    os: Mapped[str] = mapped_column(String(255), nullable=True)  # e.g. "Ubuntu 22.04"
    os_family: Mapped[str] = mapped_column(
        String(32), nullable=True
    )  # "linux" / "windows" / "macos"

    # Classification
    asset_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True
    )  # server / workstation / network / cloud / container
    criticality: Mapped[int] = mapped_column(
        Integer, nullable=False, default=3, server_default="3"
    )  # 1=low … 5=mission-critical

    # Ownership
    owner: Mapped[str] = mapped_column(String(255), nullable=True)
    department: Mapped[str] = mapped_column(String(255), nullable=True)
    location: Mapped[str] = mapped_column(String(255), nullable=True)

    # Metadata
    tags: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list, server_default="[]"
    )

    # Lifecycle
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Agent linkage
    agent_id: Mapped[str] = mapped_column(
        String(255), nullable=True
    )  # MxGuard / MxWatch agent ID

    # Detection/incident counters (denormalised for quick dashboard queries)
    detection_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    incident_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    def __repr__(self) -> str:
        return f"<Asset {self.id} {self.hostname!r} [{self.asset_type}] crit={self.criticality}>"
