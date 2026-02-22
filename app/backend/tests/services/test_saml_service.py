"""Unit tests for the SAML 2.0 service layer (feature 1.10).

Strategy:
- Mock _run_saml_login, _run_saml_acs, _run_saml_metadata so no real python3-saml
  processing is needed.
- Mock Valkey state helpers (store_oidc_state / validate_and_consume_oidc_state).
- Test user resolution, JIT provisioning, role mapping, and MFA as unit logic.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.saml_repo import SAMLProviderRepo, SAMLUserLinkRepo
from app.repositories.user_repo import UserRepo
from app.services.saml_service import (
    _build_request_data,
    _build_saml_settings,
    _get_attribute,
    _resolve_role,
    get_login_url,
    get_sp_metadata,
    handle_acs,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_CERT = "CertBodyWithoutHeadersHere"
_FAKE_NAME_ID = "samluser@idp.example.com"
_FAKE_ATTRS: dict = {"email": [_FAKE_NAME_ID], "displayName": ["SAML User"]}
_BASE_URL = "https://app.example.com"


async def _make_provider(db: AsyncSession, **overrides):
    defaults = {
        "name": "test-idp",
        "display_name": "Test IdP",
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


# ---------------------------------------------------------------------------
# _build_saml_settings
# ---------------------------------------------------------------------------


class TestBuildSamlSettings:
    async def test_https_base_url(self, db_session: AsyncSession):
        provider = await _make_provider(db_session)
        settings = _build_saml_settings(provider, "https://app.example.com")
        assert settings["sp"]["entityId"] == "https://app.example.com/saml/metadata"
        assert "https://app.example.com/api/v1/auth/saml/test-idp/acs" in (
            settings["sp"]["assertionConsumerService"]["url"]
        )
        assert settings["idp"]["x509cert"] == _FAKE_CERT
        assert settings["strict"] is True

    async def test_slo_url_included(self, db_session: AsyncSession):
        provider = await _make_provider(
            db_session, idp_slo_url="https://idp.example.com/slo"
        )
        settings = _build_saml_settings(provider, _BASE_URL)
        assert settings["idp"]["singleLogoutService"]["url"] == "https://idp.example.com/slo"

    async def test_missing_slo_url_is_empty_string(self, db_session: AsyncSession):
        provider = await _make_provider(db_session, idp_slo_url=None)
        settings = _build_saml_settings(provider, _BASE_URL)
        assert settings["idp"]["singleLogoutService"]["url"] == ""


# ---------------------------------------------------------------------------
# _build_request_data
# ---------------------------------------------------------------------------


class TestBuildRequestData:
    def test_https_scheme(self):
        rd = _build_request_data("https://app.example.com", "/acs", {"SAMLResponse": "x"})
        assert rd["https"] == "on"
        assert rd["http_host"] == "app.example.com"
        assert rd["server_port"] == "443"
        assert rd["post_data"] == {"SAMLResponse": "x"}

    def test_http_scheme(self):
        rd = _build_request_data("http://localhost:8000", "/acs", {})
        assert rd["https"] == "off"
        assert rd["http_host"] == "localhost"
        assert rd["server_port"] == "8000"

    def test_default_port_https(self):
        rd = _build_request_data("https://app.example.com", "/acs", {})
        assert rd["server_port"] == "443"

    def test_default_port_http(self):
        rd = _build_request_data("http://app.example.com", "/acs", {})
        assert rd["server_port"] == "80"


# ---------------------------------------------------------------------------
# _get_attribute
# ---------------------------------------------------------------------------


class TestGetAttribute:
    def test_returns_first_value(self):
        attrs = {"email": ["a@b.com", "c@d.com"]}
        assert _get_attribute(attrs, "email") == "a@b.com"

    def test_missing_attribute_returns_empty(self):
        assert _get_attribute({}, "missing") == ""

    def test_empty_list_returns_empty(self):
        assert _get_attribute({"email": []}, "email") == ""


# ---------------------------------------------------------------------------
# _resolve_role
# ---------------------------------------------------------------------------


class TestResolveRole:
    async def test_no_role_attribute_returns_default(self, db_session: AsyncSession):
        provider = await _make_provider(db_session, default_role="viewer")
        assert _resolve_role({}, provider) == "viewer"

    async def test_role_mapped_from_attribute(self, db_session: AsyncSession):
        provider = await _make_provider(
            db_session,
            role_attribute="groups",
            role_mapping={"saml-admins": "admin"},
            default_role="viewer",
        )
        attrs = {"groups": ["saml-admins"]}
        assert _resolve_role(attrs, provider) == "admin"

    async def test_first_matching_role_returned(self, db_session: AsyncSession):
        provider = await _make_provider(
            db_session,
            role_attribute="groups",
            role_mapping={"hunters": "hunter", "engineers": "engineer"},
            default_role="viewer",
        )
        attrs = {"groups": ["engineers", "hunters"]}
        assert _resolve_role(attrs, provider) == "engineer"

    async def test_no_match_returns_default(self, db_session: AsyncSession):
        provider = await _make_provider(
            db_session,
            role_attribute="groups",
            role_mapping={"saml-admins": "admin"},
            default_role="analyst",
        )
        attrs = {"groups": ["unknown-group"]}
        assert _resolve_role(attrs, provider) == "analyst"

    async def test_invalid_mapped_role_skipped(self, db_session: AsyncSession):
        provider = await _make_provider(
            db_session,
            role_attribute="groups",
            role_mapping={"saml-group": "not-a-real-role"},
            default_role="analyst",
        )
        attrs = {"groups": ["saml-group"]}
        assert _resolve_role(attrs, provider) == "analyst"

    async def test_invalid_default_falls_back_to_analyst(self, db_session: AsyncSession):
        provider = await _make_provider(db_session, default_role="superuser")
        assert _resolve_role({}, provider) == "analyst"


# ---------------------------------------------------------------------------
# get_login_url
# ---------------------------------------------------------------------------


class TestGetLoginUrl:
    async def test_unknown_provider(self, db_session: AsyncSession):
        with pytest.raises(ValueError, match="not found or inactive"):
            await get_login_url(db_session, "no-such-provider", _BASE_URL)

    async def test_inactive_provider(self, db_session: AsyncSession):
        await _make_provider(db_session, is_active=False)
        with pytest.raises(ValueError, match="not found or inactive"):
            await get_login_url(db_session, "test-idp", _BASE_URL)

    async def test_success_returns_redirect_and_state(self, db_session: AsyncSession):
        await _make_provider(db_session)
        fake_url = "https://idp.example.com/sso?SAMLRequest=abc&RelayState=xyz"

        with (
            patch(
                "app.services.saml_service.store_oidc_state",
                new_callable=AsyncMock,
            ) as mock_store,
            patch(
                "app.services.saml_service._run_saml_login",
                return_value=fake_url,
            ),
        ):
            result = await get_login_url(db_session, "test-idp", _BASE_URL)

        assert result.redirect_url == fake_url
        assert result.relay_state
        mock_store.assert_awaited_once()
        # relay_state passed to store_oidc_state maps to provider name
        stored_state, stored_provider = mock_store.call_args.args
        assert stored_provider == "test-idp"
        assert result.relay_state == stored_state


# ---------------------------------------------------------------------------
# handle_acs
# ---------------------------------------------------------------------------


class TestHandleACS:
    async def test_invalid_relay_state(self, db_session: AsyncSession):
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            with pytest.raises(ValueError, match="Invalid or expired SAML relay state"):
                await handle_acs(db_session, "test-idp", "resp", "bad-state", _BASE_URL)

    async def test_relay_state_provider_mismatch(self, db_session: AsyncSession):
        await _make_provider(db_session)
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="other-provider",
            ),
        ):
            with pytest.raises(ValueError, match="mismatch"):
                await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

    async def test_saml_validation_error_propagates(self, db_session: AsyncSession):
        await _make_provider(db_session)
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-idp",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                side_effect=ValueError("invalid signature"),
            ),
        ):
            with pytest.raises(ValueError, match="invalid signature"):
                await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

    async def test_missing_email_raises(self, db_session: AsyncSession):
        await _make_provider(db_session)
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-idp",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                # name_id is empty AND email attribute absent → no email
                return_value=("", "session", {}),
            ),
        ):
            with pytest.raises(ValueError, match="missing an email"):
                await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

    async def test_jit_provisioning_disabled_no_user(self, db_session: AsyncSession):
        await _make_provider(db_session, jit_provisioning=False)
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-idp",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                return_value=(_FAKE_NAME_ID, "s", _FAKE_ATTRS),
            ),
        ):
            with pytest.raises(PermissionError, match="JIT provisioning is disabled"):
                await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

    async def test_inactive_user_raises(self, db_session: AsyncSession):
        await _make_provider(db_session)
        await UserRepo.create(
            db_session,
            email=_FAKE_NAME_ID,
            hashed_password="x",
            full_name="Locked",
            role="analyst",
            is_active=False,
            must_change_password=False,
        )
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-idp",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                return_value=(_FAKE_NAME_ID, "s", _FAKE_ATTRS),
            ),
        ):
            with pytest.raises(PermissionError, match="disabled"):
                await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

    async def test_jit_create_user(self, db_session: AsyncSession):
        await _make_provider(db_session)
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-idp",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                return_value=(_FAKE_NAME_ID, "s", _FAKE_ATTRS),
            ),
        ):
            result = await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

        from app.schemas.auth import TokenResponse
        assert isinstance(result, TokenResponse)
        user = await UserRepo.get_by_email(db_session, _FAKE_NAME_ID)
        assert user is not None
        assert user.role == "analyst"
        # SAML link created
        provider = await SAMLProviderRepo.get_by_name(db_session, "test-idp")
        link = await SAMLUserLinkRepo.get_by_name_id(db_session, provider.id, _FAKE_NAME_ID)
        assert link is not None

    async def test_existing_link_resolves_user(self, db_session: AsyncSession):
        provider = await _make_provider(db_session)
        user = await UserRepo.create(
            db_session,
            email="different-email@example.com",
            hashed_password="hash",
            full_name="By Link",
            role="hunter",
            is_active=True,
            must_change_password=False,
        )
        await SAMLUserLinkRepo.create(
            db_session, user_id=user.id, provider_id=provider.id, name_id=_FAKE_NAME_ID
        )
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-idp",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                return_value=(_FAKE_NAME_ID, "s", _FAKE_ATTRS),
            ),
        ):
            result = await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

        from app.schemas.auth import TokenResponse
        assert isinstance(result, TokenResponse)
        # User should be the pre-existing one (hunter), not a new JIT user
        fetched = await UserRepo.get_by_email(db_session, "different-email@example.com")
        assert fetched.role == "hunter"

    async def test_existing_user_by_email_creates_link(self, db_session: AsyncSession):
        await _make_provider(db_session)
        await UserRepo.create(
            db_session,
            email=_FAKE_NAME_ID,
            hashed_password="hash",
            full_name="Existing",
            role="analyst",
            is_active=True,
            must_change_password=False,
        )
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-idp",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                return_value=(_FAKE_NAME_ID, "s", _FAKE_ATTRS),
            ),
        ):
            await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

        provider = await SAMLProviderRepo.get_by_name(db_session, "test-idp")
        link = await SAMLUserLinkRepo.get_by_name_id(db_session, provider.id, _FAKE_NAME_ID)
        assert link is not None

    async def test_mfa_enabled_returns_mfa_token(self, db_session: AsyncSession):
        await _make_provider(db_session)
        user = await UserRepo.create(
            db_session,
            email=_FAKE_NAME_ID,
            hashed_password="hash",
            full_name="MFA",
            role="analyst",
            is_active=True,
            must_change_password=False,
        )
        user.mfa_enabled = True
        await db_session.flush()

        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-idp",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                return_value=(_FAKE_NAME_ID, "s", _FAKE_ATTRS),
            ),
        ):
            result = await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

        from app.schemas.auth import MfaLoginResponse
        assert isinstance(result, MfaLoginResponse)
        assert result.mfa_token

    async def test_last_login_at_updated(self, db_session: AsyncSession):
        await _make_provider(db_session)
        user = await UserRepo.create(
            db_session,
            email=_FAKE_NAME_ID,
            hashed_password="hash",
            full_name="User",
            role="analyst",
            is_active=True,
            must_change_password=False,
        )
        assert user.last_login_at is None

        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-idp",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                return_value=(_FAKE_NAME_ID, "s", _FAKE_ATTRS),
            ),
        ):
            await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

        await db_session.refresh(user)
        assert user.last_login_at is not None

    async def test_role_mapping_on_jit(self, db_session: AsyncSession):
        await _make_provider(
            db_session,
            role_attribute="groups",
            role_mapping={"saml-admins": "admin"},
            default_role="viewer",
        )
        attrs = {**_FAKE_ATTRS, "groups": ["saml-admins"]}
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-idp",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                return_value=(_FAKE_NAME_ID, "s", attrs),
            ),
        ):
            await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

        user = await UserRepo.get_by_email(db_session, _FAKE_NAME_ID)
        assert user.role == "admin"

    async def test_name_id_used_as_email_fallback(self, db_session: AsyncSession):
        """When attributes dict has no email key, use NameID as email."""
        await _make_provider(db_session)
        with (
            patch(
                "app.services.saml_service.validate_and_consume_oidc_state",
                new_callable=AsyncMock,
                return_value="test-idp",
            ),
            patch(
                "app.services.saml_service._run_saml_acs",
                # No email attribute — only NameID
                return_value=(_FAKE_NAME_ID, "s", {}),
            ),
        ):
            result = await handle_acs(db_session, "test-idp", "resp", "state", _BASE_URL)

        from app.schemas.auth import TokenResponse
        assert isinstance(result, TokenResponse)
        user = await UserRepo.get_by_email(db_session, _FAKE_NAME_ID)
        assert user is not None


# ---------------------------------------------------------------------------
# get_sp_metadata
# ---------------------------------------------------------------------------


class TestGetSpMetadata:
    async def test_unknown_provider(self, db_session: AsyncSession):
        with pytest.raises(ValueError, match="not found or inactive"):
            await get_sp_metadata(db_session, "no-such-provider", _BASE_URL)

    async def test_inactive_provider(self, db_session: AsyncSession):
        await _make_provider(db_session, is_active=False)
        with pytest.raises(ValueError, match="not found or inactive"):
            await get_sp_metadata(db_session, "test-idp", _BASE_URL)

    async def test_success(self, db_session: AsyncSession):
        await _make_provider(db_session)
        fake_xml = '<?xml version="1.0"?><md:EntityDescriptor/>'

        with patch(
            "app.services.saml_service._run_saml_metadata",
            return_value=fake_xml,
        ):
            xml = await get_sp_metadata(db_session, "test-idp", _BASE_URL)

        assert xml == fake_xml

    async def test_metadata_error_propagates(self, db_session: AsyncSession):
        await _make_provider(db_session)
        with patch(
            "app.services.saml_service._run_saml_metadata",
            side_effect=ValueError("SP metadata validation failed: bad cert"),
        ):
            with pytest.raises(ValueError, match="bad cert"):
                await get_sp_metadata(db_session, "test-idp", _BASE_URL)
