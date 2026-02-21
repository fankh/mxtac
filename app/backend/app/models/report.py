"""Report ORM model — persists generated report metadata and content."""

from __future__ import annotations

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class Report(Base, TimestampMixin):
    """Stores report metadata and generated content.

    status lifecycle: generating → ready | failed
    """

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )
    template_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="generating", index=True
    )
    format: Mapped[str] = mapped_column(
        String(10), nullable=False, default="json"
    )
    # Stores from_date, to_date, and any template-specific params as ISO strings
    params_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # Generated report content (set when status="ready")
    content_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Error message (set when status="failed")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The user who requested the report (email)
    created_by: Mapped[str] = mapped_column(
        String(254), nullable=False, index=True
    )
