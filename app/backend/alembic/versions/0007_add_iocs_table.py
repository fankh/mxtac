"""Add iocs table for Indicator of Compromise threat intelligence (feature 29.1)

Revision ID: 0007
Revises: 0006
Create Date: 2026-02-21
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "iocs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("ioc_type", sa.String(20), nullable=False),
        sa.Column("value", sa.String(2048), nullable=False),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Integer, nullable=False, server_default="50"),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("tags", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("hit_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("ioc_type", "value", name="uq_ioc_type_value"),
    )
    op.create_index("ix_iocs_ioc_type", "iocs", ["ioc_type"])
    op.create_index("ix_iocs_value", "iocs", ["value"])
    op.create_index("ix_iocs_type_value", "iocs", ["ioc_type", "value"])


def downgrade() -> None:
    op.drop_index("ix_iocs_type_value", table_name="iocs")
    op.drop_index("ix_iocs_value", table_name="iocs")
    op.drop_index("ix_iocs_ioc_type", table_name="iocs")
    op.drop_table("iocs")
