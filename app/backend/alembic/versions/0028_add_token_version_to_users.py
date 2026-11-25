"""Add token_version to users.

Every access and refresh token carries the token version of its account.  A
password change increments the column, which ends all sessions of the account.

Revision ID: 0028
Revises: 0027
Create Date: 2026-11-25
"""

import sqlalchemy as sa

from alembic import op

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("users", "token_version")
