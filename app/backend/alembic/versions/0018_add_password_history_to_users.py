"""Add password_history to users table (feature 2.4)

Revision ID: 0018
Revises: 0017
Create Date: 2026-02-22
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "password_history",
            sa.JSON(),
            nullable=True,
            server_default=None,
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "password_history")
