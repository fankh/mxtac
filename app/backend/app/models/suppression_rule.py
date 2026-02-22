from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin


class SuppressionRule(Base, TimestampMixin):
    """Alert suppression / whitelist rule.

    A rule suppresses an alert when ALL non-null match fields match (AND logic).
    Fields left as NULL are treated as wildcards (match everything).

    At least one of (rule_id, host, technique_id, tactic, severity) must be
    set when the rule is created.
    """

    __tablename__ = "suppression_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Human-readable label (unique per installation)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    reason: Mapped[str] = mapped_column(String(1000), nullable=True)

    # --- Match fields (AND logic; NULL = wildcard) ---
    # Sigma rule_id — exact match
    rule_id: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    # Hostname — supports fnmatch patterns (e.g. "win-*", "srv-dc01")
    host: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    # MITRE technique ID (e.g. "T1059.001") — exact match
    technique_id: Mapped[str] = mapped_column(String(50), nullable=True, index=True)
    # ATT&CK tactic (e.g. "Execution") — exact match, case-insensitive
    tactic: Mapped[str] = mapped_column(String(100), nullable=True, index=True)
    # Severity level — exact match ("critical", "high", "medium", "low")
    severity: Mapped[str] = mapped_column(String(20), nullable=True, index=True)

    # --- Lifecycle ---
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="1"
    )
    # Optional automatic expiry (NULL = never expires)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- Audit ---
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)

    # --- Hit tracking ---
    hit_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    last_hit_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_suppression_rules_active", "is_active"),
        Index("ix_suppression_rules_expires_at", "expires_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"<SuppressionRule {self.id} name={self.name!r} active={self.is_active}>"
        )
