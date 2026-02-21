"""SavedQuery model — persists named hunt queries for later reuse."""

from __future__ import annotations

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class SavedQuery(Base, TimestampMixin):
    """A named hunt query saved by a user for later reuse.

    Stores the free-text query string, structured filter list (JSON), and time
    range so that the full search can be reconstructed and replayed.
    """

    __tablename__ = "saved_queries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Free-text Lucene query (may be empty)
    query: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Structured filter list — serialized as JSON array of {field, operator, value}
    filters: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # Time range in OpenSearch relative format (e.g. "now-24h", "now-7d")
    time_from: Mapped[str] = mapped_column(String(50), nullable=False, default="now-24h")
    time_to: Mapped[str] = mapped_column(String(50), nullable=False, default="now")

    # Owner — the email of the user who created the query
    created_by: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
