"""SSO / OIDC endpoints (feature 1.9).

Public flow:
  GET  /auth/sso/providers               → list active providers (login page)
  GET  /auth/sso/{provider}/authorize    → begin OIDC flow, get redirect URL
  POST /auth/sso/{provider}/callback     → exchange code for MxTac tokens

Admin management (requires users:write / admin role):
  POST   /auth/sso/admin/providers           → create provider
  GET    /auth/sso/admin/providers           → list all providers
  PATCH  /auth/sso/admin/providers/{id}      → update provider
  DELETE /auth/sso/admin/providers/{id}      → deactivate provider
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.oidc_repo import OIDCProviderRepo
from ....schemas.sso import (
    SSOAuthorizeResponse,
    SSOCallbackRequest,
    SSOProviderCreate,
    SSOProviderPublic,
    SSOProviderResponse,
    SSOProviderUpdate,
)
from ....services import oidc_service

router = APIRouter(prefix="/auth/sso", tags=["sso"])


# ---------------------------------------------------------------------------
# Public endpoints — no authentication required
# ---------------------------------------------------------------------------


@router.get("/providers", response_model=list[SSOProviderPublic])
async def list_active_providers(db: AsyncSession = Depends(get_db)):
    """Return the list of active SSO providers for display on the login page."""
    providers = await OIDCProviderRepo.list_active(db)
    return [SSOProviderPublic(name=p.name, display_name=p.display_name) for p in providers]


@router.get("/{provider_name}/authorize", response_model=SSOAuthorizeResponse)
async def authorize(
    provider_name: str,
    redirect_uri: str = Query(..., min_length=1, max_length=2048),
    db: AsyncSession = Depends(get_db),
):
    """Initiate an OIDC authorization-code flow.

    Returns a ``redirect_url`` that the frontend must redirect the user to, plus
    the ``state`` token that the frontend must echo back in the callback request.

    ``redirect_uri`` is the frontend callback page where the IdP will send the
    authorization code (e.g. ``https://app.example.com/sso/callback``).
    """
    try:
        return await oidc_service.get_authorization_url(db, provider_name, redirect_uri)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post("/{provider_name}/callback")
async def callback(
    provider_name: str,
    body: SSOCallbackRequest,
    db: AsyncSession = Depends(get_db),
):
    """Complete the OIDC flow and issue MxTac tokens.

    The frontend calls this after the IdP has redirected back with ``code`` and
    ``state``.  Returns a ``TokenResponse`` (or ``MfaLoginResponse`` if MFA is
    configured on the user's account).
    """
    try:
        return await oidc_service.handle_callback(db, provider_name, body)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


# ---------------------------------------------------------------------------
# Admin endpoints — require users:write (admin role)
# ---------------------------------------------------------------------------


@router.post(
    "/admin/providers",
    response_model=SSOProviderResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("users:write"))],
)
async def create_provider(body: SSOProviderCreate, db: AsyncSession = Depends(get_db)):
    """Create a new OIDC provider configuration (admin only)."""
    existing = await OIDCProviderRepo.get_by_name(db, body.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Provider with name '{body.name}' already exists",
        )

    encrypted_secret = oidc_service.encrypt_client_secret(body.client_secret)
    provider = await OIDCProviderRepo.create(
        db,
        name=body.name,
        display_name=body.display_name,
        discovery_url=body.discovery_url,
        client_id=body.client_id,
        client_secret_encrypted=encrypted_secret,
        scopes=body.scopes,
        jit_provisioning=body.jit_provisioning,
        default_role=body.default_role,
        role_claim=body.role_claim,
        role_mapping=body.role_mapping,
    )
    return provider


@router.get(
    "/admin/providers",
    response_model=list[SSOProviderResponse],
    dependencies=[Depends(require_permission("users:read"))],
)
async def list_all_providers(db: AsyncSession = Depends(get_db)):
    """List all OIDC providers including inactive ones (admin only)."""
    return await OIDCProviderRepo.list_all(db)


@router.patch(
    "/admin/providers/{provider_id}",
    response_model=SSOProviderResponse,
    dependencies=[Depends(require_permission("users:write"))],
)
async def update_provider(
    provider_id: str,
    body: SSOProviderUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update an OIDC provider's configuration (admin only)."""
    updates: dict = body.model_dump(exclude_none=True)

    # Re-encrypt client_secret if it was updated
    if "client_secret" in updates:
        updates["client_secret_encrypted"] = oidc_service.encrypt_client_secret(
            updates.pop("client_secret")
        )

    provider = await OIDCProviderRepo.update(db, provider_id, **updates)
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")
    return provider


@router.delete(
    "/admin/providers/{provider_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("users:write"))],
)
async def deactivate_provider(provider_id: str, db: AsyncSession = Depends(get_db)):
    """Deactivate an OIDC provider (admin only). Users with existing links are unaffected."""
    deleted = await OIDCProviderRepo.deactivate(db, provider_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")
