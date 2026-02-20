"""Add assets table for CMDB-style asset inventory (feature 30.1)

Revision ID: 0008
Revises: 0007
Create Date: 2026-02-21
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        # Identity
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("ip_addresses", sa.JSON, nullable=False, server_default="[]"),
        # OS
        sa.Column("os", sa.String(255), nullable=True),
        sa.Column("os_family", sa.String(32), nullable=True),
        # Classification
        sa.Column("asset_type", sa.String(32), nullable=False),
        sa.Column("criticality", sa.Integer, nullable=False, server_default="3"),
        # Ownership
        sa.Column("owner", sa.String(255), nullable=True),
        sa.Column("department", sa.String(255), nullable=True),
        sa.Column("location", sa.String(255), nullable=True),
        # Metadata
        sa.Column("tags", sa.JSON, nullable=False, server_default="[]"),
        # Lifecycle
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        # Agent linkage
        sa.Column("agent_id", sa.String(255), nullable=True),
        # Counters
        sa.Column("detection_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("incident_count", sa.Integer, nullable=False, server_default="0"),
        # Timestamps (TimestampMixin)
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("hostname", name="uq_assets_hostname"),
    )
    op.create_index("ix_assets_hostname", "assets", ["hostname"], unique=True)
    op.create_index("ix_assets_asset_type", "assets", ["asset_type"])


def downgrade() -> None:
    op.drop_index("ix_assets_asset_type", table_name="assets")
    op.drop_index("ix_assets_hostname", table_name="assets")
    op.drop_table("assets")
