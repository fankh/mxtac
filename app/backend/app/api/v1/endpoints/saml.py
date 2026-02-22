"""SAML 2.0 SSO endpoints (feature 1.10).

Public flow:
  GET  /auth/saml/providers               → list active providers (login page)
  GET  /auth/saml/{provider}/login        → begin SAML flow, get IdP redirect URL
  GET  /auth/saml/{provider}/metadata     → SP metadata XML (for IdP configuration)
  POST /auth/saml/{provider}/acs          → Assertion Consumer Service (IdP posts here)

Admin management (requires users:write / admin role):
  POST   /auth/saml/admin/providers           → create provider
  GET    /auth/saml/admin/providers           → list all providers
  PATCH  /auth/saml/admin/providers/{id}      → update provider
  DELETE /auth/saml/admin/providers/{id}      → deactivate provider
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....repositories.saml_repo import SAMLProviderRepo
from ....schemas.saml import (
    SAMLLoginResponse,
    SAMLProviderCreate,
    SAMLProviderPublic,
    SAMLProviderResponse,
    SAMLProviderUpdate,
)
from ....services import saml_service

router = APIRouter(prefix="/auth/saml", tags=["saml"])


def _base_url(request: Request) -> str:
    """Extract the application base URL from the incoming request."""
    return str(request.base_url).rstrip("/")


# ---------------------------------------------------------------------------
# Public endpoints — no authentication required
# ---------------------------------------------------------------------------


@router.get("/providers", response_model=list[SAMLProviderPublic])
async def list_active_providers(db: AsyncSession = Depends(get_db)):
    """Return the list of active SAML providers for display on the login page."""
    providers = await SAMLProviderRepo.list_active(db)
    return [SAMLProviderPublic(name=p.name, display_name=p.display_name) for p in providers]


@router.get("/{provider_name}/login", response_model=SAMLLoginResponse)
async def saml_login(
    provider_name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Initiate a SAML 2.0 SP-initiated login flow.

    Returns a ``redirect_url`` that the frontend must redirect the user to (the
    IdP's SSO endpoint with a SAMLRequest parameter) and the ``relay_state``
    token that the IdP will echo back in the ACS POST.
    """
    try:
        return await saml_service.get_login_url(db, provider_name, _base_url(request))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get("/{provider_name}/metadata")
async def sp_metadata(
    provider_name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Return the SP metadata XML for configuring this provider at the IdP.

    IdP administrators import this XML to establish the trust relationship.
    """
    try:
        xml = await saml_service.get_sp_metadata(db, provider_name, _base_url(request))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    return Response(content=xml, media_type="application/xml")


@router.post("/{provider_name}/acs")
async def acs(
    provider_name: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    saml_response: str = Form(..., alias="SAMLResponse"),
    relay_state: str = Form(default="", alias="RelayState"),
):
    """Assertion Consumer Service — receives the SAML response from the IdP.

    The IdP posts here after the user authenticates.  Returns a ``TokenResponse``
    (or ``MfaLoginResponse`` if MFA is configured on the user's account).

    Accepts ``application/x-www-form-urlencoded`` with ``SAMLResponse`` and
    ``RelayState`` fields (standard HTTP-POST binding).
    """
    try:
        return await saml_service.handle_acs(
            db, provider_name, saml_response, relay_state, _base_url(request)
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))


# ---------------------------------------------------------------------------
# Admin endpoints — require users:write (admin role)
# ---------------------------------------------------------------------------


@router.post(
    "/admin/providers",
    response_model=SAMLProviderResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("users:write"))],
)
async def create_provider(body: SAMLProviderCreate, db: AsyncSession = Depends(get_db)):
    """Create a new SAML provider configuration (admin only)."""
    existing = await SAMLProviderRepo.get_by_name(db, body.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"SAML provider '{body.name}' already exists",
        )
    provider = await SAMLProviderRepo.create(db, **body.model_dump())
    return provider


@router.get(
    "/admin/providers",
    response_model=list[SAMLProviderResponse],
    dependencies=[Depends(require_permission("users:read"))],
)
async def list_all_providers(db: AsyncSession = Depends(get_db)):
    """List all SAML providers including inactive ones (admin only)."""
    return await SAMLProviderRepo.list_all(db)


@router.patch(
    "/admin/providers/{provider_id}",
    response_model=SAMLProviderResponse,
    dependencies=[Depends(require_permission("users:write"))],
)
async def update_provider(
    provider_id: str,
    body: SAMLProviderUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update a SAML provider's configuration (admin only)."""
    updates = body.model_dump(exclude_none=True)
    provider = await SAMLProviderRepo.update(db, provider_id, **updates)
    if not provider:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")
    return provider


@router.delete(
    "/admin/providers/{provider_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission("users:write"))],
)
async def deactivate_provider(provider_id: str, db: AsyncSession = Depends(get_db)):
    """Deactivate a SAML provider (admin only). Existing user links are unaffected."""
    deleted = await SAMLProviderRepo.deactivate(db, provider_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")
