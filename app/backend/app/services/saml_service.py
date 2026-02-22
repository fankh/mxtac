"""SAML 2.0 SSO service (feature 1.10).

Design decisions:
- python3-saml performs synchronous XML/signature processing; we run it in
  asyncio's default thread pool via run_in_executor so FastAPI stays non-blocking.
- Relay-state tokens reuse the existing OIDC Valkey state store
  (store_oidc_state / validate_and_consume_oidc_state) since both serve the
  same CSRF-protection purpose and the token is provider-type-agnostic.
- User resolution order: SAMLUserLink (name_id) → email → JIT provisioning.
- The IdP x509 cert is public-key material and stored in plaintext (unlike
  OIDC client secrets, which require Fernet encryption).
- All python3-saml imports are deferred to the sync helper functions so the
  module can be imported in test environments where the library may not be
  installed, and so that the functions can be easily mocked in tests.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timezone
from functools import partial
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import settings
from ..core.security import create_access_token, create_mfa_token, create_refresh_token
from ..core.valkey import store_oidc_state, validate_and_consume_oidc_state
from ..models.saml_provider import SAMLProvider
from ..repositories.saml_repo import SAMLProviderRepo, SAMLUserLinkRepo
from ..repositories.user_repo import UserRepo
from ..schemas.saml import SAMLLoginResponse
from ..schemas.auth import MfaLoginResponse, TokenResponse

logger = logging.getLogger(__name__)

# Roles that are valid for JIT-provisioned users
_VALID_ROLES = {"viewer", "analyst", "hunter", "engineer", "admin"}


# ---------------------------------------------------------------------------
# python3-saml bridge helpers
# These thin wrappers are module-level so they can be patched in tests.
# ---------------------------------------------------------------------------


def _build_saml_settings(provider: SAMLProvider, base_url: str) -> dict[str, Any]:
    """Build the python3-saml settings dict for a given provider and base URL."""
    acs_url = f"{base_url}/api/v1/auth/saml/{provider.name}/acs"
    sls_url = f"{base_url}/api/v1/auth/saml/{provider.name}/sls"
    return {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": provider.sp_entity_id,
            "assertionConsumerService": {
                "url": acs_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "singleLogoutService": {
                "url": sls_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "NameIDFormat": provider.name_id_format,
            "x509cert": "",
            "privateKey": "",
        },
        "idp": {
            "entityId": provider.idp_entity_id,
            "singleSignOnService": {
                "url": provider.idp_sso_url,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "singleLogoutService": {
                "url": provider.idp_slo_url or "",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": provider.idp_x509_cert,
        },
    }


def _build_request_data(
    base_url: str,
    script_name: str,
    post_data: dict[str, str],
) -> dict[str, Any]:
    """Build the request_data dict expected by python3-saml's OneLogin_Saml2_Auth."""
    parsed = urlparse(base_url)
    https = "on" if parsed.scheme == "https" else "off"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return {
        "https": https,
        "http_host": parsed.hostname or "localhost",
        "server_port": str(port),
        "script_name": script_name,
        "get_data": {},
        "post_data": post_data,
        "query_string": "",
    }


def _run_saml_login(
    settings_dict: dict[str, Any],
    request_data: dict[str, Any],
    relay_state: str,
) -> str:
    """Synchronous: build a SAML AuthnRequest and return the IdP redirect URL.

    This function is run in the thread pool executor; do not await it directly.
    Deferred import keeps the module importable even if python3-saml is absent.
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import-untyped]

    auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_dict)
    return auth.login(return_to=relay_state)


def _run_saml_acs(
    settings_dict: dict[str, Any],
    request_data: dict[str, Any],
) -> tuple[str, str, dict[str, list[str]]]:
    """Synchronous: validate a SAMLResponse and return (name_id, session_index, attributes).

    Raises ValueError if the SAML response is invalid or authentication fails.
    This function is run in the thread pool executor; do not await it directly.
    """
    from onelogin.saml2.auth import OneLogin_Saml2_Auth  # type: ignore[import-untyped]

    auth = OneLogin_Saml2_Auth(request_data, old_settings=settings_dict)
    auth.process_response()
    errors = auth.get_errors()
    if errors or not auth.is_authenticated():
        reason = auth.get_last_error_reason() or ", ".join(errors)
        raise ValueError(f"SAML response validation failed: {reason}")

    name_id: str = auth.get_nameid() or ""
    session_index: str = auth.get_session_index() or ""
    attributes: dict[str, list[str]] = auth.get_attributes()
    return name_id, session_index, attributes


def _run_saml_metadata(settings_dict: dict[str, Any]) -> str:
    """Synchronous: generate SP metadata XML from the given settings.

    Raises ValueError if the generated metadata is invalid.
    This function is run in the thread pool executor; do not await it directly.
    """
    from onelogin.saml2.settings import OneLogin_Saml2_Settings  # type: ignore[import-untyped]

    saml_settings = OneLogin_Saml2_Settings(settings=settings_dict, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if errors:
        raise ValueError(f"SP metadata validation failed: {', '.join(errors)}")
    return metadata


# ---------------------------------------------------------------------------
# Public service API
# ---------------------------------------------------------------------------


async def get_login_url(
    db: AsyncSession,
    provider_name: str,
    base_url: str,
) -> SAMLLoginResponse:
    """Generate a SAML AuthnRequest and return the IdP redirect URL.

    Args:
        db: Database session.
        provider_name: Slug of the SAML provider (e.g. "okta-saml").
        base_url: Base URL of this application (e.g. "https://app.example.com").

    Returns:
        SAMLLoginResponse with redirect_url and relay_state.

    Raises:
        ValueError: If the provider does not exist or is inactive.
    """
    provider = await SAMLProviderRepo.get_by_name(db, provider_name)
    if not provider or not provider.is_active:
        raise ValueError(f"SAML provider '{provider_name}' not found or inactive")

    relay_state = secrets.token_urlsafe(32)
    # Store relay_state → provider_name for CSRF validation at ACS time
    await store_oidc_state(relay_state, provider_name)

    settings_dict = _build_saml_settings(provider, base_url)
    request_data = _build_request_data(
        base_url, f"/api/v1/auth/saml/{provider_name}/login", {}
    )

    loop = asyncio.get_event_loop()
    redirect_url: str = await loop.run_in_executor(
        None, partial(_run_saml_login, settings_dict, request_data, relay_state)
    )

    return SAMLLoginResponse(redirect_url=redirect_url, relay_state=relay_state)


async def handle_acs(
    db: AsyncSession,
    provider_name: str,
    saml_response: str,
    relay_state: str,
    base_url: str,
) -> TokenResponse | MfaLoginResponse:
    """Validate a SAML Assertion and issue MxTac tokens.

    Steps:
    1. Validate and consume the relay_state (CSRF protection).
    2. Parse and validate the SAMLResponse using python3-saml.
    3. Extract the NameID and configured attribute claims.
    4. Resolve the user: SAMLUserLink → email → JIT provisioning.
    5. Update last_login_at and return MxTac access/refresh tokens.

    Raises:
        ValueError: On any SAML protocol error.
        PermissionError: If the user is inactive or JIT provisioning is off.
    """
    # 1. CSRF validation — relay_state is one-time use
    stored_provider = await validate_and_consume_oidc_state(relay_state)
    if stored_provider is None:
        raise ValueError("Invalid or expired SAML relay state")
    if stored_provider != provider_name:
        raise ValueError("Relay state provider mismatch")

    provider = await SAMLProviderRepo.get_by_name(db, provider_name)
    if not provider or not provider.is_active:
        raise ValueError(f"SAML provider '{provider_name}' not found or inactive")

    # 2. Validate SAMLResponse
    settings_dict = _build_saml_settings(provider, base_url)
    request_data = _build_request_data(
        base_url,
        f"/api/v1/auth/saml/{provider_name}/acs",
        {"SAMLResponse": saml_response, "RelayState": relay_state},
    )

    loop = asyncio.get_event_loop()
    name_id, _session_index, attributes = await loop.run_in_executor(
        None, partial(_run_saml_acs, settings_dict, request_data)
    )

    # 3. Extract email and display name from SAML attributes
    email = _get_attribute(attributes, provider.email_attribute) or name_id
    if not email:
        raise ValueError(
            "SAML assertion is missing an email — configure email_attribute correctly"
        )

    display_name = ""
    if provider.name_attribute:
        display_name = _get_attribute(attributes, provider.name_attribute)

    # 4. User resolution: link → email → JIT
    link = await SAMLUserLinkRepo.get_by_name_id(db, provider.id, name_id)
    if link:
        user = await UserRepo.get_by_id(db, link.user_id)
    else:
        user = await UserRepo.get_by_email(db, email)

    if user is None:
        if not provider.jit_provisioning:
            raise PermissionError(
                "No local account found for this identity and JIT provisioning is disabled"
            )
        role = _resolve_role(attributes, provider)
        user = await UserRepo.create(
            db,
            email=email,
            hashed_password="",  # SAML users have no local password
            full_name=display_name,
            role=role,
            is_active=True,
            must_change_password=False,
        )
        logger.info(
            "JIT-provisioned new user email=%s via SAML provider=%s", email, provider_name
        )

    if not user.is_active:
        raise PermissionError("Account is disabled")

    # Create SAML link on first login
    if not link:
        await SAMLUserLinkRepo.create(
            db, user_id=user.id, provider_id=provider.id, name_id=name_id
        )

    # 5. Update last_login_at
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


async def get_sp_metadata(
    db: AsyncSession,
    provider_name: str,
    base_url: str,
) -> str:
    """Return the SP metadata XML for configuring the IdP.

    Raises:
        ValueError: If the provider is not found, inactive, or metadata is invalid.
    """
    provider = await SAMLProviderRepo.get_by_name(db, provider_name)
    if not provider or not provider.is_active:
        raise ValueError(f"SAML provider '{provider_name}' not found or inactive")

    settings_dict = _build_saml_settings(provider, base_url)

    loop = asyncio.get_event_loop()
    metadata: str = await loop.run_in_executor(
        None, partial(_run_saml_metadata, settings_dict)
    )
    return metadata


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_attribute(attributes: dict[str, list[str]], attr_name: str) -> str:
    """Extract the first value of a SAML attribute, or return empty string."""
    values = attributes.get(attr_name, [])
    return values[0] if values else ""


def _resolve_role(attributes: dict[str, list[str]], provider: SAMLProvider) -> str:
    """Determine the MxTac role for a JIT-provisioned user from SAML attributes.

    Checks provider.role_attribute in the assertion attributes and maps through
    provider.role_mapping.  Falls back to provider.default_role if no match.
    """
    if provider.role_attribute and provider.role_mapping:
        for val in attributes.get(provider.role_attribute, []):
            mapped = provider.role_mapping.get(str(val))
            if mapped and mapped in _VALID_ROLES:
                return mapped

    return provider.default_role if provider.default_role in _VALID_ROLES else "analyst"
