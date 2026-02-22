"""OIDC/SSO service — orchestrates the full OAuth2/OIDC authorization-code flow.

Design decisions:
- Uses httpx (already in dependencies) for all HTTP calls to the IdP.
- Uses python-jose (already in dependencies) for ID-token JWT validation.
- Discovery documents and JWKS are cached in memory (per-process) with a
  1-hour TTL to avoid hammering the IdP on every login.
- The client_secret is Fernet-encrypted in the DB (same pattern as MFA secrets).
- State tokens are stored in Valkey (or in-memory fallback) for CSRF protection.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from datetime import datetime, timezone
from typing import Any

import httpx
from cryptography.fernet import Fernet
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import settings
from ..core.security import create_access_token, create_mfa_token, create_refresh_token
from ..core.valkey import store_oidc_state, validate_and_consume_oidc_state
from ..models.oidc_provider import OIDCProvider
from ..repositories.oidc_repo import OIDCProviderRepo, OIDCUserLinkRepo
from ..repositories.user_repo import UserRepo
from ..schemas.sso import SSOAuthorizeResponse, SSOCallbackRequest
from ..schemas.auth import MfaLoginResponse, TokenResponse

logger = logging.getLogger(__name__)

# Roles that are valid for JIT-provisioned users
_VALID_ROLES = {"viewer", "analyst", "hunter", "engineer", "admin"}

# ---------------------------------------------------------------------------
# Encryption helpers (same pattern as auth.py MFA secrets)
# ---------------------------------------------------------------------------


def _get_fernet() -> Fernet:
    key_bytes = hashlib.sha256(settings.secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def encrypt_client_secret(plaintext: str) -> str:
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_client_secret(ciphertext: str) -> str:
    return _get_fernet().decrypt(ciphertext.encode()).decode()


# ---------------------------------------------------------------------------
# OIDC discovery / JWKS cache
# ---------------------------------------------------------------------------

# {discovery_url: (timestamp, document_dict)}
_discovery_cache: dict[str, tuple[float, dict[str, Any]]] = {}
# {jwks_uri: (timestamp, jwks_dict)}
_jwks_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_TTL = 3600  # 1 hour


async def _fetch_discovery(discovery_url: str) -> dict[str, Any]:
    """Fetch and cache the OIDC discovery document."""
    now = time.monotonic()
    if discovery_url in _discovery_cache:
        ts, doc = _discovery_cache[discovery_url]
        if now - ts < _CACHE_TTL:
            return doc

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(discovery_url)
        response.raise_for_status()
        doc = response.json()

    _discovery_cache[discovery_url] = (now, doc)
    return doc


async def _fetch_jwks(jwks_uri: str) -> dict[str, Any]:
    """Fetch and cache the provider's JSON Web Key Set."""
    now = time.monotonic()
    if jwks_uri in _jwks_cache:
        ts, jwks = _jwks_cache[jwks_uri]
        if now - ts < _CACHE_TTL:
            return jwks

    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(jwks_uri)
        response.raise_for_status()
        jwks = response.json()

    _jwks_cache[jwks_uri] = (now, jwks)
    return jwks


# ---------------------------------------------------------------------------
# ID token validation
# ---------------------------------------------------------------------------


def _validate_id_token(
    id_token: str,
    jwks: dict[str, Any],
    client_id: str,
    issuer: str,
) -> dict[str, Any]:
    """Validate an OIDC ID token and return its claims.

    Uses python-jose to verify signature, issuer, audience and expiry.
    Raises ValueError if validation fails.
    """
    from jose import jwt as jose_jwt, JWTError

    try:
        claims = jose_jwt.decode(
            id_token,
            jwks,
            algorithms=["RS256", "ES256", "RS384", "ES384", "RS512"],
            audience=client_id,
            issuer=issuer,
            options={"verify_at_hash": False},
        )
    except JWTError as exc:
        raise ValueError(f"ID token validation failed: {exc}") from exc

    return claims


# ---------------------------------------------------------------------------
# Public service API
# ---------------------------------------------------------------------------


async def get_authorization_url(
    db: AsyncSession,
    provider_name: str,
    redirect_uri: str,
) -> SSOAuthorizeResponse:
    """Build an OIDC authorization URL and persist the state token.

    Args:
        db: Database session.
        provider_name: Slug of the OIDC provider (e.g. "keycloak").
        redirect_uri: URI the IdP will redirect back to after authentication.
            This is typically the frontend callback page.

    Returns:
        SSOAuthorizeResponse with redirect_url and state.

    Raises:
        ValueError: If the provider does not exist or is inactive.
    """
    provider = await OIDCProviderRepo.get_by_name(db, provider_name)
    if not provider or not provider.is_active:
        raise ValueError(f"SSO provider '{provider_name}' not found or inactive")

    discovery = await _fetch_discovery(provider.discovery_url)
    authorization_endpoint: str = discovery["authorization_endpoint"]

    state = secrets.token_urlsafe(32)
    await store_oidc_state(state, provider_name)

    scopes = " ".join(provider.scopes) if provider.scopes else "openid email profile"

    params = {
        "response_type": "code",
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
    }
    redirect_url = str(httpx.URL(authorization_endpoint, params=params))

    return SSOAuthorizeResponse(redirect_url=redirect_url, state=state)


async def _exchange_code(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> dict[str, Any] | None:
    """POST the authorization code to the IdP's token endpoint.

    Returns the parsed JSON response dict on HTTP 200, or None on any error.
    Extracted as a standalone function so tests can patch it without affecting
    the httpx client used by the test framework itself.
    """
    async with httpx.AsyncClient(timeout=15) as http:
        response = await http.post(
            token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )

    if response.status_code != 200:
        logger.warning(
            "OIDC token exchange failed status=%d body=%s",
            response.status_code,
            response.text[:200],
        )
        return None

    return response.json()


async def handle_callback(
    db: AsyncSession,
    provider_name: str,
    body: SSOCallbackRequest,
) -> TokenResponse | MfaLoginResponse:
    """Complete the OIDC authorization-code flow and issue MxTac tokens.

    Steps:
    1. Validate and consume the state token (CSRF).
    2. Exchange the authorization code for tokens at the IdP's token endpoint.
    3. Validate the ID token signature and standard claims.
    4. Extract the user's email and subject from the claims.
    5. Look up an existing OIDCUserLink or find user by email.
    6. If neither exists and JIT provisioning is enabled, create the user.
    7. Update last_login_at and return MxTac access/refresh tokens.

    Raises:
        ValueError: On any OIDC protocol error.
        PermissionError: If the user is inactive or JIT provisioning is off.
    """
    # 1. Validate CSRF state
    stored_provider = await validate_and_consume_oidc_state(body.state)
    if stored_provider is None:
        raise ValueError("Invalid or expired SSO state token")
    if stored_provider != provider_name:
        raise ValueError("State token provider mismatch")

    provider = await OIDCProviderRepo.get_by_name(db, provider_name)
    if not provider or not provider.is_active:
        raise ValueError(f"SSO provider '{provider_name}' not found or inactive")

    # 2. Fetch discovery and exchange code for tokens
    discovery = await _fetch_discovery(provider.discovery_url)
    token_endpoint: str = discovery["token_endpoint"]
    issuer: str = discovery["issuer"]
    jwks_uri: str = discovery["jwks_uri"]

    client_secret = decrypt_client_secret(provider.client_secret_encrypted)

    token_data = await _exchange_code(
        token_endpoint=token_endpoint,
        client_id=provider.client_id,
        client_secret=client_secret,
        code=body.code,
        redirect_uri=body.redirect_uri,
    )
    if token_data is None:
        raise ValueError("Token exchange with IdP failed")

    id_token: str | None = token_data.get("id_token")
    if not id_token:
        raise ValueError("IdP did not return an id_token")

    # 3. Validate ID token
    jwks = await _fetch_jwks(jwks_uri)
    claims = _validate_id_token(id_token, jwks, provider.client_id, issuer)

    subject: str = claims.get("sub", "")
    email: str = claims.get("email", "")
    if not subject:
        raise ValueError("ID token missing 'sub' claim")
    if not email:
        raise ValueError("ID token missing 'email' claim — ensure 'email' scope is requested")

    # 4 & 5. Look up user via OIDC link first, then by email
    link = await OIDCUserLinkRepo.get_by_subject(db, provider.id, subject)
    if link:
        user = await UserRepo.get_by_id(db, link.user_id)
    else:
        user = await UserRepo.get_by_email(db, email)

    # 6. JIT provisioning
    if user is None:
        if not provider.jit_provisioning:
            raise PermissionError(
                "No local account found for this identity and JIT provisioning is disabled"
            )
        role = _resolve_role(claims, provider)
        user = await UserRepo.create(
            db,
            email=email,
            hashed_password="",  # SSO users have no local password
            full_name=claims.get("name") or claims.get("given_name", ""),
            role=role,
            is_active=True,
            must_change_password=False,
        )
        logger.info("JIT-provisioned new user email=%s via provider=%s", email, provider_name)

    if not user.is_active:
        raise PermissionError("Account is disabled")

    # Create OIDC link if it doesn't exist yet
    if not link:
        await OIDCUserLinkRepo.create(db, user_id=user.id, provider_id=provider.id, subject=subject)

    # 7. Update last_login_at
    user.last_login_at = datetime.now(timezone.utc)
    await db.flush()

    # Honour MFA if configured
    if user.mfa_enabled:
        mfa_token = create_mfa_token(str(user.id))
        return MfaLoginResponse(mfa_token=mfa_token)

    access_token = create_access_token({"sub": user.email, "role": user.role})
    refresh_token = create_refresh_token({"sub": user.email})
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_role(claims: dict[str, Any], provider: OIDCProvider) -> str:
    """Determine the MxTac role for a JIT-provisioned user.

    Checks provider.role_claim in claims and maps the value through
    provider.role_mapping.  Falls back to provider.default_role if no match.
    """
    if provider.role_claim and provider.role_mapping:
        claim_value = claims.get(provider.role_claim)
        if isinstance(claim_value, list):
            # Groups / roles are sometimes returned as a list
            for item in claim_value:
                mapped = provider.role_mapping.get(str(item))
                if mapped and mapped in _VALID_ROLES:
                    return mapped
        elif claim_value is not None:
            mapped = provider.role_mapping.get(str(claim_value))
            if mapped and mapped in _VALID_ROLES:
                return mapped

    return provider.default_role if provider.default_role in _VALID_ROLES else "analyst"
