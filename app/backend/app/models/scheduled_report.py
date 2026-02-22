"""ScheduledReport ORM model — persists cron-based report schedule configurations."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class ScheduledReport(Base, TimestampMixin):
    """Defines an automated recurring report schedule.

    schedule: cron expression, e.g. "0 8 * * 1" (weekly Monday 8am UTC).
    params_json: template-specific generation params, plus optional
        ``period_days`` key (default 7) indicating how many days back from
        run time to include in the report.
    next_run_at: maintained by the scheduler; updated after every run.
    notification_channel_id: when set the report summary is forwarded to
        the notification channel with that id.
    """

    __tablename__ = "scheduled_reports"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=new_uuid
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    template_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    # Cron expression (UTC), e.g. "0 8 * * 1"
    schedule: Mapped[str] = mapped_column(String(100), nullable=False)
    # Template-specific params (period_days, framework, etc.)
    params_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    format: Mapped[str] = mapped_column(String(10), nullable=False, default="json")
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    # Optional: send report via this notification channel after generation
    notification_channel_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    # The user who created this schedule (email)
    created_by: Mapped[str] = mapped_column(
        String(254), nullable=False, index=True
    )
