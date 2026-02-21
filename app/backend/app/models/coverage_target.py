"""CoverageTarget model — a single configurable ATT&CK coverage threshold.

One row acts as a singleton; the target is either absent (no threshold set) or
present.  The ``enabled`` flag lets operators pause alerting without deleting
the configured value.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Float, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid

_SINGLETON_ID = "singleton"


class CoverageTarget(Base, TimestampMixin):
    """Stores the operator-configured ATT&CK coverage target (threshold).

    Attributes
    ----------
    id:
        Fixed value ``"singleton"`` — only one row ever exists.
    target_pct:
        The desired minimum coverage percentage (0–100).  An alert is raised
        when the current live coverage falls below this value.
    enabled:
        When ``True``, threshold alerting is active.  When ``False``, the
        target is stored but no alert is raised.
    label:
        Optional human-readable name (e.g. ``"Q1 2026 Goal"``).
    """

    __tablename__ = "coverage_targets"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: _SINGLETON_ID,
    )
    target_pct: Mapped[float] = mapped_column(Float, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
