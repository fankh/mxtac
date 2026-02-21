"""CoverageSnapshot model — daily ATT&CK coverage snapshots for trend analysis."""

from __future__ import annotations

from datetime import date

from sqlalchemy import Date, Float, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class CoverageSnapshot(Base, TimestampMixin):
    """A daily snapshot of ATT&CK coverage metrics.

    One row is stored per calendar date (snapshot_date is unique).  When a
    snapshot already exists for a given date it is overwritten (upsert) to
    reflect the latest coverage state as of that day.

    Used by the ``GET /api/v1/coverage/trend`` endpoint to return a time-series
    chart of coverage growth over the past N days.
    """

    __tablename__ = "coverage_snapshots"
    __table_args__ = (UniqueConstraint("snapshot_date", name="uq_coverage_snapshots_date"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    coverage_pct: Mapped[float] = mapped_column(Float, nullable=False)
    covered_count: Mapped[int] = mapped_column(Integer, nullable=False)
    total_count: Mapped[int] = mapped_column(Integer, nullable=False)
