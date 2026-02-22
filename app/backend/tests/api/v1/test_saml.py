"""Tests for SAML 2.0 SSO endpoints (feature 1.10).

Strategy:
- Use the standard db_session / client fixtures from conftest.
- Mock all python3-saml calls (_run_saml_login, _run_saml_acs, _run_saml_metadata)
  so no real IdP or X.509 certificates are required.
- Mock Valkey state helpers (store_oidc_state / validate_and_consume_oidc_state)
  to keep tests deterministic.
"""

from __future__ import annotations

from contextlib import AsyncExitStack, ExitStack
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.saml_repo import SAMLProviderRepo, SAMLUserLinkRepo
from app.repositories.user_repo import UserRepo


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

_FAKE_CERT = "MIICertBodyWithoutHeadersHere"
_FAKE_NAME_ID = "user@idp.example.com"
_FAKE_ATTRIBUTES: dict = {
    "email": ["user@idp.example.com"],
    "displayName": ["Test User"],
}


async def _make_provider(db: AsyncSession, **overrides) -> object:
    """Create an active SAML provider for tests."""
    defaults = {
        "name": "test-saml",
        "display_name": "Test SAML IdP",
        "idp_entity_id": "https://idp.example.com/saml",
        "idp_sso_url": "https://idp.example.com/sso",
        "idp_slo_url": None,
        "idp_x509_cert": _FAKE_CERT,
        "sp_entity_id": "https://app.example.com/saml/metadata",
        "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        "email_attribute": "email",
        "name_attribute": "displayName",
        "role_attribute": None,
        "role_mapping": None,
        "is_active": True,
        "jit_provisioning": True,
        "default_role": "analyst",
    }
    defaults.update(overrides)
    return await SAMLProviderRepo.create(db, **defaults)


def _acs_context(
    name_id: str = _FAKE_NAME_ID,
    attributes: dict | None = None,
    relay_state_provider: str = "test-saml",
) -> ExitStack:
    """Return an ExitStack with all SAML ACS patches active."""
    if attributes is None:
        attributes = _FAKE_ATTRIBUTES
    stack = ExitStack()
    stack.enter_context(
        patch(
            "app.services.saml_service.validate_and_consume_oidc_state",
            new_callable=AsyncMock,
            return_value=relay_state_provider,
        )
    )
    stack.enter_context(
        patch(
            "app.services.saml_service._run_saml_acs",
            return_value=(name_id, "session-1", attributes),
        )
    )
    return stack


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------


class TestListActiveProviders:
    async def test_empty(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/saml/providers")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_returns_active_only(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(db_session, name="active-saml", display_name="Active")
        await _make_provider(db_session, name="inactive-saml", display_name="Inactive", is_active=False)

        resp = await client.get("/api/v1/auth/saml/providers")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["name"] == "active-saml"
        assert data[0]["display_name"] == "Active"


class TestSAMLLogin:
    async def test_unknown_provider(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/saml/nonexistent/login")
        assert resp.status_code == 404

    async def test_inactive_provider(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(db_session, is_active=False)
        resp = await client.get("/api/v1/auth/saml/test-saml/login")
        assert resp.status_code == 404

    async def test_success(self, client: AsyncClient, db_session: AsyncSession):
        await _make_provider(db_session)
        fake_redirect = "https://idp.example.com/sso?SAMLRequest=abc123&RelayState=xyz"

        with (
            patch(
                "app.services.saml_service.store_oidc_state",
                new_callable=AsyncMock,
            ),
            patch(
                "app.services.saml_service._run_saml_login",
                return_value=fake_redirect,
            ),
        ):
            resp = await client.get("/api/v1/auth/saml/test-saml/login")

        assert resp.status_code == 200
        data = resp.json()
        assert data["redirect_url"] == fake_redirect
        assert "relay_state" in data
        assert len(data["relay_state"]) > 10


class TestSPMetadata:
    async def test_unknown_provider(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/saml/nonexistent/metadata")
        assert resp.status_code == 404

    async def test_inactive_provider(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(db_session, is_active=False)
        resp = await client.get("/api/v1/auth/saml/test-saml/metadata")
        assert resp.status_code == 404

    async def test_success(self, client: AsyncClient, db_session: AsyncSession):
        await _make_provider(db_session)
        fake_xml = '<?xml version="1.0"?><EntityDescriptor/>'

        with patch(
            "app.services.saml_service._run_saml_metadata",
            return_value=fake_xml,
        ):
            resp = await client.get("/api/v1/auth/saml/test-saml/metadata")

        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/xml")
        assert resp.text == fake_xml


class TestACS:
    async def test_invalid_relay_state(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(db_session)
        with patch(
            "app.services.saml_service.validate_and_consume_oidc_state",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await client.post(
                "/api/v1/auth/saml/test-saml/acs",
                data={"SAMLResponse": "base64data", "RelayState": "stale-token"},
            )
        assert resp.status_code == 400
        assert "relay state" in resp.json()["detail"].lower()

    async def test_relay_state_provider_mismatch(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(db_session)
        with patch(
            "app.services.saml_service.validate_and_consume_oidc_state",
            new_callable=AsyncMock,
            return_value="different-provider",
        ):
            resp = await client.post(
                "/api/v1/auth/saml/test-saml/acs",
                data={"SAMLResponse": "base64data", "RelayState": "some-token"},
            )
        assert resp.status_code == 400
        assert "mismatch" in resp.json()["detail"].lower()

    async def test_saml_validation_error(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(db_session)
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-saml",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                side_effect=ValueError("SAML response validation failed: invalid signature"),
            ),
        ):
            resp = await client.post(
                "/api/v1/auth/saml/test-saml/acs",
                data={"SAMLResponse": "badinput", "RelayState": "tok"},
            )
        assert resp.status_code == 400
        assert "invalid signature" in resp.json()["detail"]

    async def test_jit_disabled_no_user(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(db_session, jit_provisioning=False)
        with _acs_context():
            resp = await client.post(
                "/api/v1/auth/saml/test-saml/acs",
                data={"SAMLResponse": "data", "RelayState": "tok"},
            )
        assert resp.status_code == 403
        assert "jit" in resp.json()["detail"].lower()

    async def test_inactive_user(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(db_session)
        await UserRepo.create(
            db_session,
            email=_FAKE_NAME_ID,
            hashed_password="x",
            full_name="Locked User",
            role="analyst",
            is_active=False,
            must_change_password=False,
        )
        with _acs_context():
            resp = await client.post(
                "/api/v1/auth/saml/test-saml/acs",
                data={"SAMLResponse": "data", "RelayState": "tok"},
            )
        assert resp.status_code == 403
        assert "disabled" in resp.json()["detail"].lower()

    async def test_jit_success(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(db_session)
        with _acs_context():
            resp = await client.post(
                "/api/v1/auth/saml/test-saml/acs",
                data={"SAMLResponse": "data", "RelayState": "tok"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["expires_in"] > 0

        # User should be created
        user = await UserRepo.get_by_email(db_session, _FAKE_NAME_ID)
        assert user is not None
        assert user.role == "analyst"

    async def test_existing_user_by_link(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        provider = await _make_provider(db_session)
        # Create user and existing SAML link
        user = await UserRepo.create(
            db_session,
            email="linked@example.com",
            hashed_password="hash",
            full_name="Linked User",
            role="hunter",
            is_active=True,
            must_change_password=False,
        )
        await SAMLUserLinkRepo.create(
            db_session, user_id=user.id, provider_id=provider.id, name_id=_FAKE_NAME_ID
        )

        with _acs_context():
            resp = await client.post(
                "/api/v1/auth/saml/test-saml/acs",
                data={"SAMLResponse": "data", "RelayState": "tok"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data

    async def test_existing_user_by_email(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(db_session)
        # Pre-create user with same email as NameID — no SAML link yet
        await UserRepo.create(
            db_session,
            email=_FAKE_NAME_ID,
            hashed_password="hash",
            full_name="Existing",
            role="engineer",
            is_active=True,
            must_change_password=False,
        )

        with _acs_context():
            resp = await client.post(
                "/api/v1/auth/saml/test-saml/acs",
                data={"SAMLResponse": "data", "RelayState": "tok"},
            )
        assert resp.status_code == 200
        # A SAML link should now be created
        provider = await SAMLProviderRepo.get_by_name(db_session, "test-saml")
        link = await SAMLUserLinkRepo.get_by_name_id(db_session, provider.id, _FAKE_NAME_ID)
        assert link is not None

    async def test_mfa_enabled_returns_mfa_token(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(db_session)
        user = await UserRepo.create(
            db_session,
            email=_FAKE_NAME_ID,
            hashed_password="hash",
            full_name="MFA User",
            role="analyst",
            is_active=True,
            must_change_password=False,
        )
        user.mfa_enabled = True
        await db_session.flush()

        with _acs_context():
            resp = await client.post(
                "/api/v1/auth/saml/test-saml/acs",
                data={"SAMLResponse": "data", "RelayState": "tok"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "mfa_token" in data
        assert "access_token" not in data

    async def test_role_mapping_applied_on_jit(
        self, client: AsyncClient, db_session: AsyncSession
    ):
        await _make_provider(
            db_session,
            role_attribute="groups",
            role_mapping={"saml-admins": "admin"},
            default_role="viewer",
        )
        attrs = {**_FAKE_ATTRIBUTES, "groups": ["saml-admins"]}
        with _acs_context(attributes=attrs):
            resp = await client.post(
                "/api/v1/auth/saml/test-saml/acs",
                data={"SAMLResponse": "data", "RelayState": "tok"},
            )
        assert resp.status_code == 200
        user = await UserRepo.get_by_email(db_session, _FAKE_NAME_ID)
        assert user.role == "admin"


# ---------------------------------------------------------------------------
# Admin CRUD endpoints
# ---------------------------------------------------------------------------

_PROVIDER_BODY = {
    "name": "okta-saml",
    "display_name": "Okta SAML",
    "idp_entity_id": "https://dev-123.okta.com/saml",
    "idp_sso_url": "https://dev-123.okta.com/sso/saml",
    "idp_x509_cert": _FAKE_CERT,
    "sp_entity_id": "https://app.example.com/sp",
    "email_attribute": "email",
    "jit_provisioning": True,
    "default_role": "analyst",
}


class TestAdminCRUD:
    async def test_create_provider(
        self, client: AsyncClient, admin_headers: dict, db_session: AsyncSession
    ):
        resp = await client.post(
            "/api/v1/auth/saml/admin/providers",
            json=_PROVIDER_BODY,
            headers=admin_headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "okta-saml"
        assert data["is_active"] is True
        assert "id" in data
        # Cert is public and returned
        assert "idp_x509_cert" not in data  # Not in SAMLProviderResponse by design

    async def test_create_provider_duplicate(
        self, client: AsyncClient, admin_headers: dict, db_session: AsyncSession
    ):
        await _make_provider(db_session, name="okta-saml")
        resp = await client.post(
            "/api/v1/auth/saml/admin/providers",
            json=_PROVIDER_BODY,
            headers=admin_headers,
        )
        assert resp.status_code == 409

    async def test_create_requires_admin(
        self, client: AsyncClient, analyst_headers: dict
    ):
        resp = await client.post(
            "/api/v1/auth/saml/admin/providers",
            json=_PROVIDER_BODY,
            headers=analyst_headers,
        )
        assert resp.status_code == 403

    async def test_list_all_providers(
        self, client: AsyncClient, admin_headers: dict, db_session: AsyncSession
    ):
        await _make_provider(db_session, name="p1")
        await _make_provider(db_session, name="p2", is_active=False)

        resp = await client.get(
            "/api/v1/auth/saml/admin/providers", headers=admin_headers
        )
        assert resp.status_code == 200
        names = {p["name"] for p in resp.json()}
        assert names == {"p1", "p2"}

    async def test_update_provider(
        self, client: AsyncClient, admin_headers: dict, db_session: AsyncSession
    ):
        provider = await _make_provider(db_session)
        resp = await client.patch(
            f"/api/v1/auth/saml/admin/providers/{provider.id}",
            json={"display_name": "Updated Name", "default_role": "hunter"},
            headers=admin_headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["display_name"] == "Updated Name"
        assert data["default_role"] == "hunter"

    async def test_update_nonexistent(
        self, client: AsyncClient, admin_headers: dict
    ):
        resp = await client.patch(
            "/api/v1/auth/saml/admin/providers/no-such-id",
            json={"display_name": "X"},
            headers=admin_headers,
        )
        assert resp.status_code == 404

    async def test_deactivate_provider(
        self, client: AsyncClient, admin_headers: dict, db_session: AsyncSession
    ):
        provider = await _make_provider(db_session)
        resp = await client.delete(
            f"/api/v1/auth/saml/admin/providers/{provider.id}",
            headers=admin_headers,
        )
        assert resp.status_code == 204

        # Should not appear in public list
        resp2 = await client.get("/api/v1/auth/saml/providers")
        assert resp2.json() == []

    async def test_deactivate_nonexistent(
        self, client: AsyncClient, admin_headers: dict
    ):
        resp = await client.delete(
            "/api/v1/auth/saml/admin/providers/no-such-id",
            headers=admin_headers,
        )
        assert resp.status_code == 404
