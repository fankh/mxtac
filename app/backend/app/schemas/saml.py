"""SAML 2.0 request and response schemas (feature 1.10)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Public provider list (login page)
# ---------------------------------------------------------------------------


class SAMLProviderPublic(BaseModel):
    """Minimal provider info exposed to unauthenticated login-page callers."""

    name: str
    display_name: str


# ---------------------------------------------------------------------------
# Login / ACS flow
# ---------------------------------------------------------------------------


class SAMLLoginResponse(BaseModel):
    """Redirect URL returned to the frontend to begin the SAML flow."""

    redirect_url: str
    relay_state: str  # opaque CSRF token; IdP echoes back in ACS POST


# ---------------------------------------------------------------------------
# Admin — provider CRUD
# ---------------------------------------------------------------------------


class SAMLProviderCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9_-]+$")
    display_name: str = Field(..., min_length=1, max_length=255)
    # IdP metadata
    idp_entity_id: str = Field(..., min_length=1, max_length=2048)
    idp_sso_url: str = Field(..., min_length=10, max_length=2048)
    idp_slo_url: str | None = None
    # IdP's X.509 signing certificate — PEM body (no -----BEGIN/END----- headers)
    idp_x509_cert: str = Field(..., min_length=10)
    # SP configuration
    sp_entity_id: str = Field(..., min_length=1, max_length=2048)
    name_id_format: str = Field(
        default="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    )
    # Attribute mapping
    email_attribute: str = Field(default="email")
    name_attribute: str | None = None
    role_attribute: str | None = None
    role_mapping: dict[str, str] | None = None
    # Provisioning
    jit_provisioning: bool = True
    default_role: str = Field(default="analyst")


class SAMLProviderUpdate(BaseModel):
    display_name: str | None = None
    idp_entity_id: str | None = None
    idp_sso_url: str | None = None
    idp_slo_url: str | None = None
    idp_x509_cert: str | None = None
    sp_entity_id: str | None = None
    name_id_format: str | None = None
    email_attribute: str | None = None
    name_attribute: str | None = None
    role_attribute: str | None = None
    role_mapping: dict[str, str] | None = None
    is_active: bool | None = None
    jit_provisioning: bool | None = None
    default_role: str | None = None


class SAMLProviderResponse(BaseModel):
    """Full provider details returned to admins (IdP cert is included — it is public)."""

    id: str
    name: str
    display_name: str
    idp_entity_id: str
    idp_sso_url: str
    idp_slo_url: str | None
    sp_entity_id: str
    name_id_format: str
    email_attribute: str
    name_attribute: str | None
    role_attribute: str | None
    role_mapping: dict[str, Any] | None
    is_active: bool
    jit_provisioning: bool
    default_role: str

    model_config = {"from_attributes": True}
