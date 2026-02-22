"""Add password_changed_at to users table (feature 2.3)

Revision ID: 0017
Revises: 0016
Create Date: 2026-02-22
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: Union[str, None] = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "password_changed_at",
            sa.DateTime(timezone=True),
            nullable=True,
            server_default=None,
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "password_changed_at")
