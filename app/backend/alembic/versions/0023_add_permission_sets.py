"""Add permission_sets table and permission_set_id to api_keys (feature 3.9)

Revision ID: 0023
Revises: 0022
Create Date: 2026-02-22
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: Union[str, None] = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- permission_sets table ---
    op.create_table(
        "permission_sets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.String(1000), nullable=True),
        sa.Column("permissions", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_permission_sets_name", "permission_sets", ["name"], unique=True)
    op.create_index("ix_permission_sets_is_active", "permission_sets", ["is_active"])

    # --- api_keys: add permission_set_id column ---
    op.add_column(
        "api_keys",
        sa.Column("permission_set_id", sa.String(36), nullable=True),
    )
    op.create_index("ix_api_keys_permission_set_id", "api_keys", ["permission_set_id"])


def downgrade() -> None:
    op.drop_index("ix_api_keys_permission_set_id", table_name="api_keys")
    op.drop_column("api_keys", "permission_set_id")

    op.drop_index("ix_permission_sets_is_active", table_name="permission_sets")
    op.drop_index("ix_permission_sets_name", table_name="permission_sets")
    op.drop_table("permission_sets")
