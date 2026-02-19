from sqlalchemy import Boolean, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class Connector(Base, TimestampMixin):
    __tablename__ = "connectors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    connector_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    # wazuh | zeek | suricata | prowler | opencti | velociraptor | osquery | generic

    # Configuration stored as JSON string (encrypted in production)
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    # Status
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="inactive")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_seen_at: Mapped[str] = mapped_column(String(50), nullable=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)

    # Metrics
    events_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    errors_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    def __repr__(self) -> str:
        return f"<Connector {self.name} type={self.connector_type} status={self.status}>"
