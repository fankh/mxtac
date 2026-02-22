"""SAML 2.0 provider and user-link models (feature 1.10 — SSO/SAML)."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class SAMLProvider(Base, TimestampMixin):
    """Configured SAML 2.0 identity providers.

    Admins create providers via the SSO management API; the SAML flow reads
    from this table at runtime to build AuthnRequests and validate Assertions.
    """

    __tablename__ = "saml_providers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)

    # Human-friendly identifier used in API paths (e.g. "okta-saml", "adfs")
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    # Label shown on the login page button
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # IdP metadata — obtained from the IdP's metadata XML or admin console
    idp_entity_id: Mapped[str] = mapped_column(String(2048), nullable=False)
    idp_sso_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    # SLO endpoint is optional; omit if the IdP does not support single logout
    idp_slo_url: Mapped[str | None] = mapped_column(String(2048), nullable=True, default=None)
    # IdP's X.509 signing certificate — PEM body only (no -----BEGIN/END----- headers)
    idp_x509_cert: Mapped[str] = mapped_column(Text, nullable=False)

    # SP (our service provider) configuration
    sp_entity_id: Mapped[str] = mapped_column(String(2048), nullable=False)
    name_id_format: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        default="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    )

    # SAML attribute mapping — maps IdP attribute names to MxTac fields
    # The email_attribute is used to derive the user's email when NameID is not email
    email_attribute: Mapped[str] = mapped_column(String(256), nullable=False, default="email")
    # Optional display name attribute (e.g. "displayName", "cn")
    name_attribute: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    # Optional role claim attribute for role mapping
    role_attribute: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    # JSON dict: {<saml_attribute_value>: <mxtac_role>}
    role_mapping: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=None)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Just-in-time user provisioning — auto-create local accounts on first SSO login
    jit_provisioning: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Default role assigned to JIT-provisioned users
    default_role: Mapped[str] = mapped_column(String(50), nullable=False, default="analyst")

    def __repr__(self) -> str:
        return f"<SAMLProvider {self.name} active={self.is_active}>"


class SAMLUserLink(Base):
    """Maps a SAML NameID to a local MxTac user account.

    Created on first SSO login; subsequent logins look up the existing link
    so that a local user can be found even if their email changes at the IdP.
    """

    __tablename__ = "saml_user_links"
    __table_args__ = (
        UniqueConstraint("provider_id", "name_id", name="uq_saml_link_provider_nameid"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("saml_providers.id", ondelete="CASCADE"), nullable=False
    )
    # SAML NameID — unique per provider; used as the stable identity anchor
    name_id: Mapped[str] = mapped_column(String(512), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<SAMLUserLink provider={self.provider_id} nameid={self.name_id[:16]}…>"
