"""OIDC provider and user-link models (feature 1.9 — SSO/OIDC)."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, JSON, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class OIDCProvider(Base, TimestampMixin):
    """Configured OIDC identity providers (Keycloak, Okta, Azure AD, …).

    Admins create providers via the SSO management API; the OIDC flow reads
    from this table at runtime to build authorization URLs and exchange tokens.
    """

    __tablename__ = "oidc_providers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)

    # Human-friendly identifier used in API paths (e.g. "keycloak", "okta")
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    # Label shown on the login page button
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # OIDC discovery document URL, e.g.:
    #   Keycloak: https://keycloak.example.com/realms/mxtac/.well-known/openid-configuration
    #   Okta:     https://dev-123.okta.com/.well-known/openid-configuration
    #   Azure AD: https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration
    discovery_url: Mapped[str] = mapped_column(String(2048), nullable=False)

    # OAuth2 client credentials — client_secret is stored Fernet-encrypted
    client_id: Mapped[str] = mapped_column(String(512), nullable=False)
    client_secret_encrypted: Mapped[str] = mapped_column(String(2048), nullable=False)

    # Space-separated OIDC scopes (default: "openid email profile")
    scopes: Mapped[list] = mapped_column(
        JSON, nullable=False, default=lambda: ["openid", "email", "profile"]
    )

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Just-in-time user provisioning — auto-create local accounts on first SSO login
    jit_provisioning: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Default role assigned to JIT-provisioned users
    default_role: Mapped[str] = mapped_column(String(50), nullable=False, default="analyst")

    # Optional role claim mapping: OIDC claim name that carries the user's role
    # (e.g. "groups", "roles").  When set and jit_provisioning is True, the
    # claim value is mapped through role_mapping to a MxTac role.
    role_claim: Mapped[str | None] = mapped_column(String(100), nullable=True, default=None)
    # JSON dict: {<claim_value>: <mxtac_role>} — e.g. {"mxtac-admins": "admin"}
    role_mapping: Mapped[dict | None] = mapped_column(JSON, nullable=True, default=None)

    def __repr__(self) -> str:
        return f"<OIDCProvider {self.name} active={self.is_active}>"


class OIDCUserLink(Base):
    """Maps an OIDC subject (sub) to a local MxTac user account.

    Created on first SSO login; subsequent logins look up the existing link
    so that a local user can be found even if their email changes at the IdP.
    """

    __tablename__ = "oidc_user_links"
    __table_args__ = (
        UniqueConstraint("provider_id", "subject", name="uq_oidc_link_provider_subject"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("oidc_providers.id", ondelete="CASCADE"), nullable=False
    )
    # OIDC sub claim — unique per provider, never changes for a given identity
    subject: Mapped[str] = mapped_column(String(512), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<OIDCUserLink provider={self.provider_id} sub={self.subject[:16]}…>"
