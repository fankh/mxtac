"""Add OIDC provider and user-link tables (feature 1.9 — SSO/OIDC)

Revision ID: 0021
Revises: 0020
Create Date: 2026-02-22
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oidc_providers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("discovery_url", sa.String(2048), nullable=False),
        sa.Column("client_id", sa.String(512), nullable=False),
        sa.Column("client_secret_encrypted", sa.String(2048), nullable=False),
        sa.Column("scopes", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("jit_provisioning", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("default_role", sa.String(50), nullable=False, server_default="analyst"),
        sa.Column("role_claim", sa.String(100), nullable=True),
        sa.Column("role_mapping", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_oidc_providers_name", "oidc_providers", ["name"])

    op.create_table(
        "oidc_user_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider_id", sa.String(36), sa.ForeignKey("oidc_providers.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("provider_id", "subject", name="uq_oidc_link_provider_subject"),
    )
    op.create_index("ix_oidc_user_links_user_id", "oidc_user_links", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_oidc_user_links_user_id", table_name="oidc_user_links")
    op.drop_table("oidc_user_links")
    op.drop_index("ix_oidc_providers_name", table_name="oidc_providers")
    op.drop_table("oidc_providers")
