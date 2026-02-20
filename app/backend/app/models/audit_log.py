from datetime import datetime, timezone

from sqlalchemy import DateTime, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, new_uuid


class AuditLog(Base):
    """Database-backed audit trail entry.

    Captures every security-relevant action with who, what, on which resource,
    and when — satisfying compliance requirements without depending on OpenSearch.
    """

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )

    # When
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # Who
    actor: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )  # user email or system identity

    # What
    action: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # create | update | delete | login | logout | export | …

    # On which resource
    resource_type: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )  # rule | connector | user | incident | detection | …
    resource_id: Mapped[str] = mapped_column(
        String(255), nullable=True
    )  # primary key of the resource

    # Extra context
    details: Mapped[dict] = mapped_column(
        JSON, nullable=True
    )  # arbitrary key-value context

    # HTTP request metadata
    request_ip: Mapped[str] = mapped_column(String(45), nullable=True)   # IPv4 or IPv6
    request_method: Mapped[str] = mapped_column(String(16), nullable=True)
    request_path: Mapped[str] = mapped_column(String(1024), nullable=True)
    user_agent: Mapped[str] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return (
            f"<AuditLog {self.id} actor={self.actor!r} "
            f"action={self.action!r} resource={self.resource_type}/{self.resource_id}>"
        )
