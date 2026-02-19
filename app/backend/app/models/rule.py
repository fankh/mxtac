from sqlalchemy import Boolean, Integer, String, Text, ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class Rule(Base, TimestampMixin):
    __tablename__ = "rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    rule_type: Mapped[str] = mapped_column(String(30), nullable=False, default="sigma")  # sigma, correlation
    content: Mapped[str] = mapped_column(Text, nullable=False)   # raw YAML
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="experimental")
    level: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # ATT&CK mapping
    logsource_product: Mapped[str] = mapped_column(String(100), nullable=True)
    logsource_category: Mapped[str] = mapped_column(String(100), nullable=True)
    logsource_service: Mapped[str] = mapped_column(String(100), nullable=True)
    technique_ids: Mapped[str] = mapped_column(Text, nullable=True)  # JSON array string
    tactic_ids: Mapped[str] = mapped_column(Text, nullable=True)     # JSON array string

    # Stats
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fp_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_hit_at: Mapped[str] = mapped_column(String(50), nullable=True)

    # Ownership
    created_by: Mapped[str] = mapped_column(String(255), nullable=True)
    source: Mapped[str] = mapped_column(String(100), nullable=True)  # sigmaHQ, custom

    def __repr__(self) -> str:
        return f"<Rule {self.id} {self.level} '{self.title}'>"
