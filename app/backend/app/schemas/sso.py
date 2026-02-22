"""SSO / OIDC request and response schemas (feature 1.9)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Public provider list (login page)
# ---------------------------------------------------------------------------


class SSOProviderPublic(BaseModel):
    """Minimal provider info exposed to unauthenticated login-page callers."""

    name: str
    display_name: str


# ---------------------------------------------------------------------------
# Authorization flow
# ---------------------------------------------------------------------------


class SSOAuthorizeResponse(BaseModel):
    """Redirect URL returned to the frontend to begin the OIDC flow."""

    redirect_url: str
    state: str  # opaque CSRF token; frontend echoes back in callback


class SSOCallbackRequest(BaseModel):
    """Code + state submitted by the frontend after the IdP redirects back."""

    code: str = Field(..., min_length=1, max_length=2048)
    state: str = Field(..., min_length=1, max_length=512)
    # The redirect_uri the frontend originally used in the authorization request.
    # Must match exactly what was sent to the IdP.
    redirect_uri: str = Field(..., min_length=1, max_length=2048)


# ---------------------------------------------------------------------------
# Admin — provider CRUD
# ---------------------------------------------------------------------------


class SSOProviderCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9_-]+$")
    display_name: str = Field(..., min_length=1, max_length=255)
    discovery_url: str = Field(..., min_length=10, max_length=2048)
    client_id: str = Field(..., min_length=1, max_length=512)
    client_secret: str = Field(..., min_length=1, max_length=2048)
    scopes: list[str] = Field(default=["openid", "email", "profile"])
    jit_provisioning: bool = True
    default_role: str = Field(default="analyst")
    role_claim: str | None = None
    role_mapping: dict[str, str] | None = None


class SSOProviderUpdate(BaseModel):
    display_name: str | None = None
    discovery_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: list[str] | None = None
    is_active: bool | None = None
    jit_provisioning: bool | None = None
    default_role: str | None = None
    role_claim: str | None = None
    role_mapping: dict[str, str] | None = None


class SSOProviderResponse(BaseModel):
    """Full provider details returned to admins (no client_secret)."""

    id: str
    name: str
    display_name: str
    discovery_url: str
    client_id: str
    scopes: list[Any]
    is_active: bool
    jit_provisioning: bool
    default_role: str
    role_claim: str | None
    role_mapping: dict[str, Any] | None

    model_config = {"from_attributes": True}
