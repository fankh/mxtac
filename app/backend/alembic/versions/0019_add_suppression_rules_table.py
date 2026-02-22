"""Add suppression_rules table (feature 9.11)

Revision ID: 0019
Revises: 0018
Create Date: 2026-02-22
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: Union[str, None] = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "suppression_rules",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=True),
        # Match fields
        sa.Column("rule_id", sa.String(255), nullable=True),
        sa.Column("host", sa.String(255), nullable=True),
        sa.Column("technique_id", sa.String(50), nullable=True),
        sa.Column("tactic", sa.String(100), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        # Lifecycle
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        # Audit
        sa.Column("created_by", sa.String(255), nullable=False),
        # Hit tracking
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_hit_at", sa.DateTime(timezone=True), nullable=True),
        # Timestamps
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_suppression_rules_name"),
    )
    op.create_index("ix_suppression_rules_name", "suppression_rules", ["name"], unique=True)
    op.create_index("ix_suppression_rules_rule_id", "suppression_rules", ["rule_id"])
    op.create_index("ix_suppression_rules_host", "suppression_rules", ["host"])
    op.create_index("ix_suppression_rules_technique_id", "suppression_rules", ["technique_id"])
    op.create_index("ix_suppression_rules_tactic", "suppression_rules", ["tactic"])
    op.create_index("ix_suppression_rules_severity", "suppression_rules", ["severity"])
    op.create_index("ix_suppression_rules_active", "suppression_rules", ["is_active"])
    op.create_index("ix_suppression_rules_expires_at", "suppression_rules", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_suppression_rules_expires_at", table_name="suppression_rules")
    op.drop_index("ix_suppression_rules_active", table_name="suppression_rules")
    op.drop_index("ix_suppression_rules_severity", table_name="suppression_rules")
    op.drop_index("ix_suppression_rules_tactic", table_name="suppression_rules")
    op.drop_index("ix_suppression_rules_technique_id", table_name="suppression_rules")
    op.drop_index("ix_suppression_rules_host", table_name="suppression_rules")
    op.drop_index("ix_suppression_rules_rule_id", table_name="suppression_rules")
    op.drop_index("ix_suppression_rules_name", table_name="suppression_rules")
    op.drop_table("suppression_rules")
