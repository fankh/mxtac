"""Tests for SSO / OIDC endpoints (feature 1.9).

Strategy:
- Use the standard db_session / client fixtures from conftest.
- Mock all outbound HTTP calls (OIDC discovery, JWKS, token exchange) with
  unittest.mock.patch so no real IdP is needed.
- Patch app.services.oidc_service._exchange_code (not httpx.AsyncClient.post)
  so the httpx test client used by the test framework is unaffected.
- Mock Valkey helpers (store_oidc_state / validate_and_consume_oidc_state)
  to keep tests deterministic.
"""

from __future__ import annotations

import time
import types
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.oidc_repo import OIDCProviderRepo, OIDCUserLinkRepo
from app.repositories.user_repo import UserRepo
from app.services.oidc_service import encrypt_client_secret, decrypt_client_secret


# ---------------------------------------------------------------------------
# Shared fixtures / helpers
# ---------------------------------------------------------------------------

_DISCOVERY_DOC = {
    "issuer": "https://idp.example.com",
    "authorization_endpoint": "https://idp.example.com/authorize",
    "token_endpoint": "https://idp.example.com/token",
    "jwks_uri": "https://idp.example.com/jwks",
}

_JWKS = {"keys": []}

# Fake IdP token-endpoint response
_IDP_TOKEN_DATA = {"id_token": "fake.id.token", "access_token": "idp-at"}


def _fake_id_token_claims(
    subject: str = "sub-abc123",
    email: str = "sso-user@example.com",
    name: str = "SSO User",
) -> dict:
    return {
        "sub": subject,
        "email": email,
        "name": name,
        "iss": "https://idp.example.com",
        "aud": "test-client-id",
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }


async def _make_provider(db: AsyncSession, **overrides) -> object:
    """Create an active OIDC provider for tests."""
    defaults = {
        "name": "test-idp",
        "display_name": "Test IdP",
        "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
        "client_id": "test-client-id",
        "client_secret_encrypted": encrypt_client_secret("test-secret"),
        "scopes": ["openid", "email", "profile"],
        "is_active": True,
        "jit_provisioning": True,
        "default_role": "analyst",
    }
    defaults.update(overrides)
    return await OIDCProviderRepo.create(db, **defaults)


def _callback_patches(claims: dict, token_data: dict | None = None):
    """Return a list of context managers that mock all outbound OIDC calls."""
    if token_data is None:
        token_data = _IDP_TOKEN_DATA
    return [
        patch(
            "app.services.oidc_service.validate_and_consume_oidc_state",
            new_callable=AsyncMock,
            return_value="test-idp",
        ),
        patch(
            "app.services.oidc_service._fetch_discovery",
            new_callable=AsyncMock,
            return_value=_DISCOVERY_DOC,
        ),
        patch(
            "app.services.oidc_service._exchange_code",
            new_callable=AsyncMock,
            return_value=token_data,
        ),
        patch(
            "app.services.oidc_service._fetch_jwks",
            new_callable=AsyncMock,
            return_value=_JWKS,
        ),
        patch(
            "app.services.oidc_service._validate_id_token",
            return_value=claims,
        ),
    ]


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_round_trip():
    plaintext = "super-secret-client-secret"
    encrypted = encrypt_client_secret(plaintext)
    assert encrypted != plaintext
    assert decrypt_client_secret(encrypted) == plaintext


# ---------------------------------------------------------------------------
# GET /auth/sso/providers — list active providers
# ---------------------------------------------------------------------------


async def test_list_providers_empty(client: AsyncClient):
    resp = await client.get("/api/v1/auth/sso/providers")
    assert resp.status_code == 200
    assert resp.json() == []


async def test_list_providers_returns_active_only(client: AsyncClient, db_session: AsyncSession):
    await _make_provider(db_session, name="active-idp", display_name="Active IdP")
    await _make_provider(db_session, name="inactive-idp", display_name="Inactive IdP", is_active=False)
    await db_session.commit()

    resp = await client.get("/api/v1/auth/sso/providers")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["name"] == "active-idp"
    assert data[0]["display_name"] == "Active IdP"
    # client_secret must never appear
    assert "client_secret" not in data[0]
    assert "client_secret_encrypted" not in data[0]


# ---------------------------------------------------------------------------
# GET /auth/sso/{provider}/authorize — initiate OIDC flow
# ---------------------------------------------------------------------------


async def test_authorize_unknown_provider(client: AsyncClient):
    with patch(
        "app.services.oidc_service._fetch_discovery",
        new_callable=AsyncMock,
        return_value=_DISCOVERY_DOC,
    ):
        resp = await client.get(
            "/api/v1/auth/sso/nonexistent/authorize",
            params={"redirect_uri": "https://app.example.com/callback"},
        )
    assert resp.status_code == 404


async def test_authorize_returns_redirect_url(client: AsyncClient, db_session: AsyncSession):
    await _make_provider(db_session)
    await db_session.commit()

    with (
        patch(
            "app.services.oidc_service._fetch_discovery",
            new_callable=AsyncMock,
            return_value=_DISCOVERY_DOC,
        ),
        patch(
            "app.services.oidc_service.store_oidc_state",
            new_callable=AsyncMock,
        ) as mock_store,
    ):
        resp = await client.get(
            "/api/v1/auth/sso/test-idp/authorize",
            params={"redirect_uri": "https://app.example.com/callback"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "redirect_url" in data
    assert "state" in data
    assert "https://idp.example.com/authorize" in data["redirect_url"]
    assert "client_id=test-client-id" in data["redirect_url"]
    assert data["state"] in data["redirect_url"]
    mock_store.assert_called_once()


async def test_authorize_inactive_provider(client: AsyncClient, db_session: AsyncSession):
    await _make_provider(db_session, is_active=False)
    await db_session.commit()

    with patch(
        "app.services.oidc_service._fetch_discovery",
        new_callable=AsyncMock,
        return_value=_DISCOVERY_DOC,
    ):
        resp = await client.get(
            "/api/v1/auth/sso/test-idp/authorize",
            params={"redirect_uri": "https://app.example.com/callback"},
        )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /auth/sso/{provider}/callback — complete OIDC flow
# ---------------------------------------------------------------------------


async def test_callback_invalid_state(client: AsyncClient, db_session: AsyncSession):
    await _make_provider(db_session)
    await db_session.commit()

    with patch(
        "app.services.oidc_service.validate_and_consume_oidc_state",
        new_callable=AsyncMock,
        return_value=None,  # state not found
    ):
        resp = await client.post(
            "/api/v1/auth/sso/test-idp/callback",
            json={"code": "auth-code", "state": "invalid-state", "redirect_uri": "https://app.example.com/callback"},
        )
    assert resp.status_code == 400
    assert "state" in resp.json()["detail"].lower()


async def test_callback_state_provider_mismatch(client: AsyncClient, db_session: AsyncSession):
    await _make_provider(db_session)
    await db_session.commit()

    with patch(
        "app.services.oidc_service.validate_and_consume_oidc_state",
        new_callable=AsyncMock,
        return_value="other-provider",  # different provider stored
    ):
        resp = await client.post(
            "/api/v1/auth/sso/test-idp/callback",
            json={"code": "auth-code", "state": "some-state", "redirect_uri": "https://app.example.com/callback"},
        )
    assert resp.status_code == 400


async def test_callback_jit_creates_user_and_returns_tokens(
    client: AsyncClient, db_session: AsyncSession
):
    await _make_provider(db_session)
    await db_session.commit()

    claims = _fake_id_token_claims()

    with patch.multiple(
        "app.services.oidc_service",
        validate_and_consume_oidc_state=AsyncMock(return_value="test-idp"),
        _fetch_discovery=AsyncMock(return_value=_DISCOVERY_DOC),
        _exchange_code=AsyncMock(return_value=_IDP_TOKEN_DATA),
        _fetch_jwks=AsyncMock(return_value=_JWKS),
        _validate_id_token=lambda *a, **kw: claims,
    ):
        resp = await client.post(
            "/api/v1/auth/sso/test-idp/callback",
            json={
                "code": "auth-code-xyz",
                "state": "valid-state",
                "redirect_uri": "https://app.example.com/callback",
            },
        )

    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data

    # Verify user was JIT-provisioned
    user = await UserRepo.get_by_email(db_session, "sso-user@example.com")
    assert user is not None
    assert user.role == "analyst"
    assert user.is_active is True
    assert user.hashed_password == ""  # no local password for SSO users


async def test_callback_existing_user_via_email(
    client: AsyncClient, db_session: AsyncSession
):
    """Existing user matched by email on first SSO login → link created."""
    await UserRepo.create(
        db_session,
        email="existing@example.com",
        hashed_password="not-a-real-hash",  # SSO test — password never checked
        role="hunter",
        is_active=True,
    )
    await _make_provider(db_session)
    await db_session.commit()

    claims = _fake_id_token_claims(subject="sub-existing-001", email="existing@example.com")

    with patch.multiple(
        "app.services.oidc_service",
        validate_and_consume_oidc_state=AsyncMock(return_value="test-idp"),
        _fetch_discovery=AsyncMock(return_value=_DISCOVERY_DOC),
        _exchange_code=AsyncMock(return_value=_IDP_TOKEN_DATA),
        _fetch_jwks=AsyncMock(return_value=_JWKS),
        _validate_id_token=lambda *a, **kw: claims,
    ):
        resp = await client.post(
            "/api/v1/auth/sso/test-idp/callback",
            json={
                "code": "auth-code-xyz",
                "state": "valid-state",
                "redirect_uri": "https://app.example.com/callback",
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data

    # No duplicate user created
    users = await UserRepo.list(db_session)
    emails = [u.email for u in users]
    assert emails.count("existing@example.com") == 1


async def test_callback_existing_link_used(
    client: AsyncClient, db_session: AsyncSession
):
    """Subsequent SSO logins use the stored OIDCUserLink by subject."""
    user = await UserRepo.create(
        db_session,
        email="linked@example.com",
        hashed_password="not-a-real-hash",  # SSO test — password never checked
        role="analyst",
        is_active=True,
    )
    provider = await _make_provider(db_session)
    await db_session.flush()
    await OIDCUserLinkRepo.create(
        db_session, user_id=user.id, provider_id=provider.id, subject="sub-linked-999"
    )
    await db_session.commit()

    # Claim has a DIFFERENT email — lookup should still find user via sub
    claims = _fake_id_token_claims(
        subject="sub-linked-999", email="linked-different-email@example.com"
    )

    with patch.multiple(
        "app.services.oidc_service",
        validate_and_consume_oidc_state=AsyncMock(return_value="test-idp"),
        _fetch_discovery=AsyncMock(return_value=_DISCOVERY_DOC),
        _exchange_code=AsyncMock(return_value=_IDP_TOKEN_DATA),
        _fetch_jwks=AsyncMock(return_value=_JWKS),
        _validate_id_token=lambda *a, **kw: claims,
    ):
        resp = await client.post(
            "/api/v1/auth/sso/test-idp/callback",
            json={
                "code": "auth-code-xyz",
                "state": "valid-state",
                "redirect_uri": "https://app.example.com/callback",
            },
        )

    assert resp.status_code == 200, resp.text
    # Exactly 1 user in DB (no new user created)
    users = await UserRepo.list(db_session)
    assert len(users) == 1
    assert users[0].email == "linked@example.com"


async def test_callback_jit_disabled_unknown_user_is_403(
    client: AsyncClient, db_session: AsyncSession
):
    await _make_provider(db_session, jit_provisioning=False)
    await db_session.commit()

    claims = _fake_id_token_claims(email="unknown@example.com")

    with patch.multiple(
        "app.services.oidc_service",
        validate_and_consume_oidc_state=AsyncMock(return_value="test-idp"),
        _fetch_discovery=AsyncMock(return_value=_DISCOVERY_DOC),
        _exchange_code=AsyncMock(return_value=_IDP_TOKEN_DATA),
        _fetch_jwks=AsyncMock(return_value=_JWKS),
        _validate_id_token=lambda *a, **kw: claims,
    ):
        resp = await client.post(
            "/api/v1/auth/sso/test-idp/callback",
            json={
                "code": "auth-code-xyz",
                "state": "valid-state",
                "redirect_uri": "https://app.example.com/callback",
            },
        )
    assert resp.status_code == 403


async def test_callback_inactive_user_is_403(client: AsyncClient, db_session: AsyncSession):
    user = await UserRepo.create(
        db_session,
        email="inactive@example.com",
        hashed_password="not-a-real-hash",  # SSO test — password never checked
        role="analyst",
        is_active=False,
    )
    provider = await _make_provider(db_session)
    await db_session.flush()
    await OIDCUserLinkRepo.create(
        db_session, user_id=user.id, provider_id=provider.id, subject="sub-inactive"
    )
    await db_session.commit()

    claims = _fake_id_token_claims(subject="sub-inactive", email="inactive@example.com")

    with patch.multiple(
        "app.services.oidc_service",
        validate_and_consume_oidc_state=AsyncMock(return_value="test-idp"),
        _fetch_discovery=AsyncMock(return_value=_DISCOVERY_DOC),
        _exchange_code=AsyncMock(return_value=_IDP_TOKEN_DATA),
        _fetch_jwks=AsyncMock(return_value=_JWKS),
        _validate_id_token=lambda *a, **kw: claims,
    ):
        resp = await client.post(
            "/api/v1/auth/sso/test-idp/callback",
            json={
                "code": "auth-code-xyz",
                "state": "valid-state",
                "redirect_uri": "https://app.example.com/callback",
            },
        )
    assert resp.status_code == 403


async def test_callback_token_exchange_failure(client: AsyncClient, db_session: AsyncSession):
    await _make_provider(db_session)
    await db_session.commit()

    with patch.multiple(
        "app.services.oidc_service",
        validate_and_consume_oidc_state=AsyncMock(return_value="test-idp"),
        _fetch_discovery=AsyncMock(return_value=_DISCOVERY_DOC),
        _exchange_code=AsyncMock(return_value=None),  # failure → None
    ):
        resp = await client.post(
            "/api/v1/auth/sso/test-idp/callback",
            json={
                "code": "bad-code",
                "state": "valid-state",
                "redirect_uri": "https://app.example.com/callback",
            },
        )
    assert resp.status_code == 400


async def test_callback_mfa_user_returns_mfa_token(client: AsyncClient, db_session: AsyncSession):
    """SSO login for a user with MFA enabled returns mfa_required response."""
    import pyotp
    from app.api.v1.endpoints.auth import _encrypt_secret

    user = await UserRepo.create(
        db_session,
        email="mfa-sso@example.com",
        hashed_password="not-a-real-hash",  # SSO test — password never checked
        role="analyst",
        is_active=True,
        mfa_enabled=True,
        mfa_secret=_encrypt_secret(pyotp.random_base32()),
    )
    provider = await _make_provider(db_session)
    await db_session.flush()
    await OIDCUserLinkRepo.create(
        db_session, user_id=user.id, provider_id=provider.id, subject="sub-mfa-sso"
    )
    await db_session.commit()

    claims = _fake_id_token_claims(subject="sub-mfa-sso", email="mfa-sso@example.com")

    with patch.multiple(
        "app.services.oidc_service",
        validate_and_consume_oidc_state=AsyncMock(return_value="test-idp"),
        _fetch_discovery=AsyncMock(return_value=_DISCOVERY_DOC),
        _exchange_code=AsyncMock(return_value=_IDP_TOKEN_DATA),
        _fetch_jwks=AsyncMock(return_value=_JWKS),
        _validate_id_token=lambda *a, **kw: claims,
    ):
        resp = await client.post(
            "/api/v1/auth/sso/test-idp/callback",
            json={
                "code": "auth-code-xyz",
                "state": "valid-state",
                "redirect_uri": "https://app.example.com/callback",
            },
        )

    assert resp.status_code == 200
    data = resp.json()
    assert data.get("mfa_required") is True
    assert "mfa_token" in data


# ---------------------------------------------------------------------------
# Admin endpoints — POST /auth/sso/admin/providers
# ---------------------------------------------------------------------------


async def test_create_provider_requires_admin(client: AsyncClient, analyst_headers: dict):
    resp = await client.post(
        "/api/v1/auth/sso/admin/providers",
        json={
            "name": "new-idp",
            "display_name": "New IdP",
            "discovery_url": "https://new-idp.example.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "secret",
        },
        headers=analyst_headers,
    )
    assert resp.status_code == 403


async def test_create_provider_success(client: AsyncClient, admin_headers: dict):
    resp = await client.post(
        "/api/v1/auth/sso/admin/providers",
        json={
            "name": "keycloak",
            "display_name": "Keycloak",
            "discovery_url": "https://keycloak.example.com/realms/mxtac/.well-known/openid-configuration",
            "client_id": "mxtac-client",
            "client_secret": "supersecret",
            "scopes": ["openid", "email", "profile"],
            "jit_provisioning": True,
            "default_role": "analyst",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["name"] == "keycloak"
    assert data["display_name"] == "Keycloak"
    assert data["is_active"] is True
    # client_secret must not be in response
    assert "client_secret" not in data
    assert "client_secret_encrypted" not in data


async def test_create_provider_duplicate_name_is_409(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    await _make_provider(db_session, name="dup-idp")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/auth/sso/admin/providers",
        json={
            "name": "dup-idp",
            "display_name": "Duplicate",
            "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "sec",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 409


async def test_create_provider_invalid_name_pattern(client: AsyncClient, admin_headers: dict):
    resp = await client.post(
        "/api/v1/auth/sso/admin/providers",
        json={
            "name": "UPPER CASE SPACES",  # invalid — must be lowercase slug
            "display_name": "Bad Name",
            "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
            "client_id": "cid",
            "client_secret": "sec",
        },
        headers=admin_headers,
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Admin endpoints — GET /auth/sso/admin/providers
# ---------------------------------------------------------------------------


async def test_list_all_providers_admin(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    await _make_provider(db_session, name="p1", is_active=True)
    await _make_provider(db_session, name="p2", is_active=False)
    await db_session.commit()

    resp = await client.get("/api/v1/auth/sso/admin/providers", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    names = {p["name"] for p in data}
    assert names == {"p1", "p2"}


async def test_list_all_providers_requires_admin(client: AsyncClient, analyst_headers: dict):
    resp = await client.get("/api/v1/auth/sso/admin/providers", headers=analyst_headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Admin endpoints — PATCH /auth/sso/admin/providers/{id}
# ---------------------------------------------------------------------------


async def test_update_provider_display_name(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    provider = await _make_provider(db_session)
    await db_session.commit()

    resp = await client.patch(
        f"/api/v1/auth/sso/admin/providers/{provider.id}",
        json={"display_name": "Updated IdP"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["display_name"] == "Updated IdP"


async def test_update_provider_deactivate(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    provider = await _make_provider(db_session)
    await db_session.commit()

    resp = await client.patch(
        f"/api/v1/auth/sso/admin/providers/{provider.id}",
        json={"is_active": False},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["is_active"] is False


async def test_update_provider_not_found(client: AsyncClient, admin_headers: dict):
    resp = await client.patch(
        "/api/v1/auth/sso/admin/providers/nonexistent-id",
        json={"display_name": "Nope"},
        headers=admin_headers,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Admin endpoints — DELETE /auth/sso/admin/providers/{id}
# ---------------------------------------------------------------------------


async def test_deactivate_provider(
    client: AsyncClient, admin_headers: dict, db_session: AsyncSession
):
    provider = await _make_provider(db_session)
    await db_session.commit()

    resp = await client.delete(
        f"/api/v1/auth/sso/admin/providers/{provider.id}",
        headers=admin_headers,
    )
    assert resp.status_code == 204

    # Verify it's no longer active in the public list
    resp2 = await client.get("/api/v1/auth/sso/providers")
    assert resp2.json() == []


async def test_deactivate_provider_not_found(client: AsyncClient, admin_headers: dict):
    resp = await client.delete(
        "/api/v1/auth/sso/admin/providers/ghost-id",
        headers=admin_headers,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Valkey OIDC state helpers
# ---------------------------------------------------------------------------


async def test_valkey_oidc_state_in_memory_fallback():
    """When Valkey is unavailable the in-memory fallback is used."""
    from app.core import valkey as _valkey_mod

    # Clear in-memory store
    _valkey_mod._oidc_state_store.clear()

    with patch(
        "app.core.valkey.get_valkey_client",
        side_effect=Exception("Valkey down"),
    ):
        await _valkey_mod.store_oidc_state("test-state", "keycloak")
        result = await _valkey_mod.validate_and_consume_oidc_state("test-state")

    assert result == "keycloak"
    # Consumed — state removed from in-memory store
    assert _valkey_mod._oidc_state_store.get("test-state") is None


async def test_valkey_oidc_state_consumed_once():
    """State tokens are one-time use."""
    from app.core import valkey as _valkey_mod

    _valkey_mod._oidc_state_store.clear()

    with patch(
        "app.core.valkey.get_valkey_client",
        side_effect=Exception("Valkey down"),
    ):
        await _valkey_mod.store_oidc_state("one-time", "okta")
        first = await _valkey_mod.validate_and_consume_oidc_state("one-time")
        second = await _valkey_mod.validate_and_consume_oidc_state("one-time")

    assert first == "okta"
    assert second is None


# ---------------------------------------------------------------------------
# Role mapping (_resolve_role) — pure unit tests using SimpleNamespace
# ---------------------------------------------------------------------------


def _make_ns_provider(**kwargs) -> object:
    """Create a simple namespace that mimics OIDCProvider for _resolve_role."""
    defaults = {
        "role_claim": None,
        "role_mapping": None,
        "default_role": "analyst",
    }
    defaults.update(kwargs)
    return types.SimpleNamespace(**defaults)


def test_resolve_role_from_claim():
    from app.services.oidc_service import _resolve_role

    provider = _make_ns_provider(
        role_claim="groups",
        role_mapping={"mxtac-admins": "admin", "mxtac-analysts": "analyst"},
        default_role="viewer",
    )
    claims = {"sub": "u1", "email": "u@example.com", "groups": ["mxtac-admins"]}
    assert _resolve_role(claims, provider) == "admin"


def test_resolve_role_fallback_to_default():
    from app.services.oidc_service import _resolve_role

    provider = _make_ns_provider(
        role_claim="groups",
        role_mapping={"mxtac-admins": "admin"},
        default_role="analyst",
    )
    claims = {"sub": "u1", "email": "u@example.com", "groups": ["unknown-group"]}
    assert _resolve_role(claims, provider) == "analyst"


def test_resolve_role_no_claim_config():
    from app.services.oidc_service import _resolve_role

    provider = _make_ns_provider(role_claim=None, role_mapping=None, default_role="hunter")
    claims = {"sub": "u1", "email": "u@example.com"}
    assert _resolve_role(claims, provider) == "hunter"


def test_resolve_role_string_claim():
    """Scalar (non-list) role claim is also handled."""
    from app.services.oidc_service import _resolve_role

    provider = _make_ns_provider(
        role_claim="role",
        role_mapping={"admin_group": "admin"},
        default_role="analyst",
    )
    claims = {"sub": "u1", "email": "u@example.com", "role": "admin_group"}
    assert _resolve_role(claims, provider) == "admin"
