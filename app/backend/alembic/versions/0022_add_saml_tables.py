"""Add SAML 2.0 provider and user-link tables (feature 1.10 — SSO/SAML)

Revision ID: 0022
Revises: 0021
Create Date: 2026-02-22
"""

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: Union[str, None] = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saml_providers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("display_name", sa.String(255), nullable=False),
        # IdP metadata
        sa.Column("idp_entity_id", sa.String(2048), nullable=False),
        sa.Column("idp_sso_url", sa.String(2048), nullable=False),
        sa.Column("idp_slo_url", sa.String(2048), nullable=True),
        sa.Column("idp_x509_cert", sa.Text(), nullable=False),
        # SP configuration
        sa.Column("sp_entity_id", sa.String(2048), nullable=False),
        sa.Column(
            "name_id_format",
            sa.String(256),
            nullable=False,
            server_default="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        ),
        # Attribute mapping
        sa.Column("email_attribute", sa.String(256), nullable=False, server_default="email"),
        sa.Column("name_attribute", sa.String(256), nullable=True),
        sa.Column("role_attribute", sa.String(256), nullable=True),
        sa.Column("role_mapping", sa.JSON(), nullable=True),
        # Provisioning
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("jit_provisioning", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("default_role", sa.String(50), nullable=False, server_default="analyst"),
        # Timestamps
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_saml_providers_name", "saml_providers", ["name"])

    op.create_table(
        "saml_user_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "provider_id",
            sa.String(36),
            sa.ForeignKey("saml_providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name_id", sa.String(512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("provider_id", "name_id", name="uq_saml_link_provider_nameid"),
    )
    op.create_index("ix_saml_user_links_user_id", "saml_user_links", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_saml_user_links_user_id", table_name="saml_user_links")
    op.drop_table("saml_user_links")
    op.drop_index("ix_saml_providers_name", table_name="saml_providers")
    op.drop_table("saml_providers")
