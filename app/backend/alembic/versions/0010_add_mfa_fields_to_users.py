"""Add MFA fields to users table (feature 32.1)

Revision ID: 0010
Revises: 0009
Create Date: 2026-02-21
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("mfa_secret", sa.String(512), nullable=True))
    op.add_column("users", sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("users", sa.Column("mfa_backup_codes", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "mfa_backup_codes")
    op.drop_column("users", "mfa_enabled")
    op.drop_column("users", "mfa_secret")
