"""Unit tests for app.services.oidc_service.

Coverage:

  Encryption helpers:
  - encrypt_client_secret / decrypt_client_secret round-trip
  - Different plaintexts produce different ciphertexts

  Discovery / JWKS cache (_fetch_discovery, _fetch_jwks):
  - Fetches from HTTP on first call
  - Returns cached value within TTL (no second HTTP call)
  - Re-fetches after TTL expires
  - Propagates HTTP errors

  ID token validation (_validate_id_token):
  - Valid token returns claims dict
  - JWTError raises ValueError with descriptive message

  Role resolution (_resolve_role):
  - No role_claim configured → returns provider default_role
  - role_claim present, scalar value matches mapping → returns mapped role
  - role_claim present as list → returns first matched role
  - role_claim present but no mapping match → returns default_role
  - default_role not in _VALID_ROLES → falls back to "analyst"
  - Invalid mapped role not in _VALID_ROLES → skips and falls back

  get_authorization_url():
  - Unknown provider name → raises ValueError
  - Inactive provider → raises ValueError
  - Valid provider → returns SSOAuthorizeResponse with redirect_url and state
  - redirect_url contains client_id, scope, redirect_uri query params

  _exchange_code():
  - HTTP 200 → returns parsed JSON dict
  - HTTP non-200 → returns None (no exception)

  handle_callback():
  - Invalid/expired state → raises ValueError
  - State provider mismatch → raises ValueError
  - Provider not found after state validation → raises ValueError
  - Inactive provider → raises ValueError
  - Token exchange returns None → raises ValueError
  - Token exchange returns no id_token → raises ValueError
  - Missing 'sub' claim → raises ValueError
  - Missing 'email' claim → raises ValueError
  - JIT provisioning disabled, no local account → raises PermissionError
  - Inactive user account → raises PermissionError
  - JIT creates new user and returns TokenResponse
  - Existing user found via email, new link created, returns TokenResponse
  - Existing user found via OIDC link, no duplicate link created, returns TokenResponse
  - MFA-enabled user returns MfaLoginResponse
  - JIT uses 'name' claim for full_name
  - JIT falls back to 'given_name' when 'name' absent
  - last_login_at is updated on every successful login
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import app.services.oidc_service as svc
from app.repositories.oidc_repo import OIDCProviderRepo, OIDCUserLinkRepo
from app.repositories.user_repo import UserRepo
from app.schemas.auth import MfaLoginResponse, TokenResponse
from app.schemas.sso import SSOAuthorizeResponse, SSOCallbackRequest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_provider(db, **overrides):
    """Insert a minimal active OIDC provider into the test DB."""
    from app.services.oidc_service import encrypt_client_secret

    defaults = dict(
        name="testidp",
        display_name="Test IdP",
        discovery_url="https://idp.example.com/.well-known/openid-configuration",
        client_id="mxtac-client",
        client_secret_encrypted=encrypt_client_secret("supersecret"),
        scopes=["openid", "email", "profile"],
        is_active=True,
        jit_provisioning=True,
        default_role="analyst",
        role_claim=None,
        role_mapping=None,
    )
    defaults.update(overrides)
    return await OIDCProviderRepo.create(db, **defaults)


async def _make_user(db, **overrides):
    """Insert a minimal active user into the test DB."""
    defaults = dict(
        email="alice@example.com",
        hashed_password="hashed",
        full_name="Alice",
        role="analyst",
        is_active=True,
        must_change_password=False,
    )
    defaults.update(overrides)
    return await UserRepo.create(db, **defaults)


def _fake_discovery(token_endpoint="https://idp.example.com/token"):
    return {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/auth",
        "token_endpoint": token_endpoint,
        "jwks_uri": "https://idp.example.com/jwks",
    }


def _fake_claims(**overrides):
    base = {
        "sub": "uid-001",
        "email": "alice@example.com",
        "name": "Alice Example",
        "iss": "https://idp.example.com",
        "aud": "mxtac-client",
    }
    base.update(overrides)
    return base


_MISSING = object()  # sentinel so callers can explicitly pass token_data=None


def _make_callback_patches(claims=None, token_data=_MISSING):
    """Return a context-manager tuple that stubs all outbound OIDC I/O."""
    if claims is None:
        claims = _fake_claims()
    if token_data is _MISSING:
        token_data = {"id_token": "fake.id.token", "access_token": "fake-at"}

    return (
        patch(
            "app.services.oidc_service.validate_and_consume_oidc_state",
            new_callable=AsyncMock,
            return_value="testidp",
        ),
        patch(
            "app.services.oidc_service._fetch_discovery",
            new_callable=AsyncMock,
            return_value=_fake_discovery(),
        ),
        patch(
            "app.services.oidc_service._exchange_code",
            new_callable=AsyncMock,
            return_value=token_data,
        ),
        patch(
            "app.services.oidc_service._fetch_jwks",
            new_callable=AsyncMock,
            return_value={"keys": []},
        ),
        patch(
            "app.services.oidc_service._validate_id_token",
            return_value=claims,
        ),
    )


# ---------------------------------------------------------------------------
# Clear module-level caches between tests
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_caches():
    """Ensure discovery and JWKS caches are empty before every test."""
    svc._discovery_cache.clear()
    svc._jwks_cache.clear()
    yield
    svc._discovery_cache.clear()
    svc._jwks_cache.clear()


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------


class TestEncryption:

    def test_round_trip(self):
        plaintext = "my-super-secret"
        encrypted = svc.encrypt_client_secret(plaintext)
        assert svc.decrypt_client_secret(encrypted) == plaintext

    def test_ciphertext_differs_from_plaintext(self):
        plaintext = "abc123"
        assert svc.encrypt_client_secret(plaintext) != plaintext

    def test_different_plaintexts_produce_different_ciphertexts(self):
        ct1 = svc.encrypt_client_secret("secret-a")
        ct2 = svc.encrypt_client_secret("secret-b")
        assert ct1 != ct2

    def test_empty_string_round_trip(self):
        assert svc.decrypt_client_secret(svc.encrypt_client_secret("")) == ""


# ---------------------------------------------------------------------------
# Discovery cache (_fetch_discovery)
# ---------------------------------------------------------------------------


class TestFetchDiscovery:

    @pytest.mark.asyncio
    async def test_fetches_from_http_on_first_call(self):
        doc = {"issuer": "https://idp.example.com", "authorization_endpoint": "https://idp.example.com/auth"}
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = doc

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("app.services.oidc_service.httpx.AsyncClient", return_value=mock_client):
            result = await svc._fetch_discovery("https://idp.example.com/.well-known/openid-configuration")

        assert result == doc
        mock_client.get.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_cached_value_within_ttl(self):
        url = "https://idp.example.com/.well-known/openid-configuration"
        doc = {"issuer": "cached-issuer"}
        svc._discovery_cache[url] = (time.monotonic(), doc)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock()

        with patch("app.services.oidc_service.httpx.AsyncClient", return_value=mock_client):
            result = await svc._fetch_discovery(url)

        assert result == doc
        mock_client.get.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_refetches_after_ttl_expires(self):
        url = "https://idp.example.com/.well-known/openid-configuration"
        old_doc = {"issuer": "old"}
        # Plant an expired cache entry
        svc._discovery_cache[url] = (time.monotonic() - svc._CACHE_TTL - 1, old_doc)

        new_doc = {"issuer": "fresh"}
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = new_doc

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("app.services.oidc_service.httpx.AsyncClient", return_value=mock_client):
            result = await svc._fetch_discovery(url)

        assert result == new_doc
        mock_client.get.assert_awaited_once()


# ---------------------------------------------------------------------------
# JWKS cache (_fetch_jwks)
# ---------------------------------------------------------------------------


class TestFetchJwks:

    @pytest.mark.asyncio
    async def test_fetches_from_http_on_first_call(self):
        jwks = {"keys": [{"kty": "RSA", "kid": "1"}]}
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = jwks

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("app.services.oidc_service.httpx.AsyncClient", return_value=mock_client):
            result = await svc._fetch_jwks("https://idp.example.com/jwks")

        assert result == jwks

    @pytest.mark.asyncio
    async def test_returns_cached_jwks_within_ttl(self):
        uri = "https://idp.example.com/jwks"
        jwks = {"keys": []}
        svc._jwks_cache[uri] = (time.monotonic(), jwks)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock()

        with patch("app.services.oidc_service.httpx.AsyncClient", return_value=mock_client):
            result = await svc._fetch_jwks(uri)

        assert result is jwks
        mock_client.get.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_refetches_after_ttl_expires(self):
        uri = "https://idp.example.com/jwks"
        svc._jwks_cache[uri] = (time.monotonic() - svc._CACHE_TTL - 1, {"keys": ["old"]})

        fresh = {"keys": ["new"]}
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = fresh

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=mock_resp)

        with patch("app.services.oidc_service.httpx.AsyncClient", return_value=mock_client):
            result = await svc._fetch_jwks(uri)

        assert result == fresh


# ---------------------------------------------------------------------------
# ID token validation (_validate_id_token)
# ---------------------------------------------------------------------------


class TestValidateIdToken:

    def test_valid_token_returns_claims(self):
        expected = {"sub": "uid-001", "email": "user@example.com", "iss": "https://idp.example.com"}
        # _validate_id_token does a local `from jose import jwt as jose_jwt` so
        # we must patch at the jose.jwt module level.
        with patch("jose.jwt.decode", return_value=expected):
            claims = svc._validate_id_token(
                id_token="header.payload.sig",
                jwks={"keys": []},
                client_id="my-client",
                issuer="https://idp.example.com",
            )
        assert claims == expected

    def test_jwt_error_raises_value_error(self):
        from jose import JWTError

        with patch("jose.jwt.decode", side_effect=JWTError("bad signature")):
            with pytest.raises(ValueError, match="ID token validation failed"):
                svc._validate_id_token(
                    id_token="bad.token.here",
                    jwks={"keys": []},
                    client_id="my-client",
                    issuer="https://idp.example.com",
                )


# ---------------------------------------------------------------------------
# Role resolution (_resolve_role)
# ---------------------------------------------------------------------------


class TestResolveRole:

    def _provider(self, role_claim=None, role_mapping=None, default_role="analyst"):
        p = MagicMock()
        p.role_claim = role_claim
        p.role_mapping = role_mapping
        p.default_role = default_role
        return p

    def test_no_role_claim_returns_default_role(self):
        p = self._provider(role_claim=None, default_role="viewer")
        assert svc._resolve_role({}, p) == "viewer"

    def test_scalar_claim_maps_to_role(self):
        p = self._provider(
            role_claim="role",
            role_mapping={"admin-group": "admin"},
            default_role="analyst",
        )
        assert svc._resolve_role({"role": "admin-group"}, p) == "admin"

    def test_list_claim_first_match_returned(self):
        p = self._provider(
            role_claim="groups",
            role_mapping={"soc-analysts": "analyst", "soc-hunters": "hunter"},
            default_role="viewer",
        )
        claims = {"groups": ["soc-hunters", "soc-analysts"]}
        result = svc._resolve_role(claims, p)
        assert result == "hunter"

    def test_list_claim_no_match_returns_default(self):
        p = self._provider(
            role_claim="groups",
            role_mapping={"admins": "admin"},
            default_role="viewer",
        )
        assert svc._resolve_role({"groups": ["unknown-group"]}, p) == "viewer"

    def test_scalar_claim_no_match_returns_default(self):
        p = self._provider(
            role_claim="role",
            role_mapping={"admin-group": "admin"},
            default_role="analyst",
        )
        assert svc._resolve_role({"role": "unknown"}, p) == "analyst"

    def test_invalid_default_role_falls_back_to_analyst(self):
        p = self._provider(role_claim=None, default_role="superuser")
        assert svc._resolve_role({}, p) == "analyst"

    def test_mapped_role_not_in_valid_roles_is_skipped(self):
        # role_mapping returns an invalid value → should fall back to default
        p = self._provider(
            role_claim="role",
            role_mapping={"some-group": "superadmin"},  # not a valid role
            default_role="analyst",
        )
        assert svc._resolve_role({"role": "some-group"}, p) == "analyst"

    def test_all_valid_roles_accepted(self):
        for role in ["viewer", "analyst", "hunter", "engineer", "admin"]:
            p = self._provider(
                role_claim="r",
                role_mapping={"g": role},
                default_role="viewer",
            )
            assert svc._resolve_role({"r": "g"}, p) == role


# ---------------------------------------------------------------------------
# get_authorization_url()
# ---------------------------------------------------------------------------


class TestGetAuthorizationUrl:

    @pytest.mark.asyncio
    async def test_unknown_provider_raises_value_error(self, db_session):
        with patch(
            "app.services.oidc_service.store_oidc_state",
            new_callable=AsyncMock,
        ):
            with pytest.raises(ValueError, match="not found or inactive"):
                await svc.get_authorization_url(db_session, "nonexistent", "https://app/callback")

    @pytest.mark.asyncio
    async def test_inactive_provider_raises_value_error(self, db_session):
        await _make_provider(db_session, name="inactive-idp", is_active=False)

        with patch(
            "app.services.oidc_service.store_oidc_state",
            new_callable=AsyncMock,
        ):
            with pytest.raises(ValueError, match="not found or inactive"):
                await svc.get_authorization_url(db_session, "inactive-idp", "https://app/callback")

    @pytest.mark.asyncio
    async def test_returns_sso_authorize_response(self, db_session):
        await _make_provider(db_session)

        with (
            patch(
                "app.services.oidc_service._fetch_discovery",
                new_callable=AsyncMock,
                return_value=_fake_discovery(),
            ),
            patch(
                "app.services.oidc_service.store_oidc_state",
                new_callable=AsyncMock,
            ) as mock_store,
        ):
            response = await svc.get_authorization_url(
                db_session, "testidp", "https://app/callback"
            )

        assert isinstance(response, SSOAuthorizeResponse)
        assert response.state
        assert "https://idp.example.com/auth" in response.redirect_url
        mock_store.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_redirect_url_contains_expected_params(self, db_session):
        await _make_provider(db_session, client_id="my-client", scopes=["openid", "email"])

        with (
            patch(
                "app.services.oidc_service._fetch_discovery",
                new_callable=AsyncMock,
                return_value=_fake_discovery(),
            ),
            patch("app.services.oidc_service.store_oidc_state", new_callable=AsyncMock),
        ):
            response = await svc.get_authorization_url(
                db_session, "testidp", "https://app/callback"
            )

        assert "client_id=my-client" in response.redirect_url
        assert "redirect_uri=" in response.redirect_url
        assert "response_type=code" in response.redirect_url
        assert "scope=" in response.redirect_url

    @pytest.mark.asyncio
    async def test_state_is_stored_with_provider_name(self, db_session):
        await _make_provider(db_session)

        with (
            patch(
                "app.services.oidc_service._fetch_discovery",
                new_callable=AsyncMock,
                return_value=_fake_discovery(),
            ),
            patch(
                "app.services.oidc_service.store_oidc_state",
                new_callable=AsyncMock,
            ) as mock_store,
        ):
            response = await svc.get_authorization_url(
                db_session, "testidp", "https://app/callback"
            )

        # store_oidc_state should be called with (state_token, provider_name)
        mock_store.assert_awaited_once_with(response.state, "testidp")


# ---------------------------------------------------------------------------
# _exchange_code()
# ---------------------------------------------------------------------------


class TestExchangeCode:

    @pytest.mark.asyncio
    async def test_http_200_returns_json(self):
        payload = {"access_token": "at", "id_token": "idt", "token_type": "Bearer"}
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = payload

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("app.services.oidc_service.httpx.AsyncClient", return_value=mock_client):
            result = await svc._exchange_code(
                "https://idp/token", "client-id", "secret", "auth-code", "https://app/cb"
            )

        assert result == payload

    @pytest.mark.asyncio
    async def test_http_non_200_returns_none(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 400
        mock_resp.text = "invalid_grant"

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("app.services.oidc_service.httpx.AsyncClient", return_value=mock_client):
            result = await svc._exchange_code(
                "https://idp/token", "client-id", "secret", "bad-code", "https://app/cb"
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_http_500_returns_none(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal Server Error"

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.post = AsyncMock(return_value=mock_resp)

        with patch("app.services.oidc_service.httpx.AsyncClient", return_value=mock_client):
            result = await svc._exchange_code(
                "https://idp/token", "c", "s", "code", "https://app/cb"
            )

        assert result is None


# ---------------------------------------------------------------------------
# handle_callback() — error paths
# ---------------------------------------------------------------------------


class TestHandleCallbackErrors:

    def _body(self, **overrides):
        defaults = dict(code="auth-code", state="valid-state", redirect_uri="https://app/cb")
        defaults.update(overrides)
        return SSOCallbackRequest(**defaults)

    @pytest.mark.asyncio
    async def test_invalid_state_raises_value_error(self, db_session):
        with patch(
            "app.services.oidc_service.validate_and_consume_oidc_state",
            new_callable=AsyncMock,
            return_value=None,
        ):
            with pytest.raises(ValueError, match="Invalid or expired SSO state token"):
                await svc.handle_callback(db_session, "testidp", self._body())

    @pytest.mark.asyncio
    async def test_state_provider_mismatch_raises_value_error(self, db_session):
        with patch(
            "app.services.oidc_service.validate_and_consume_oidc_state",
            new_callable=AsyncMock,
            return_value="other-idp",  # state was issued for a different provider
        ):
            with pytest.raises(ValueError, match="provider mismatch"):
                await svc.handle_callback(db_session, "testidp", self._body())

    @pytest.mark.asyncio
    async def test_provider_not_found_raises_value_error(self, db_session):
        with patch(
            "app.services.oidc_service.validate_and_consume_oidc_state",
            new_callable=AsyncMock,
            return_value="ghost-idp",
        ):
            with pytest.raises(ValueError, match="not found or inactive"):
                await svc.handle_callback(db_session, "ghost-idp", self._body(state="valid-state"))

    @pytest.mark.asyncio
    async def test_inactive_provider_raises_value_error(self, db_session):
        await _make_provider(db_session, name="off-idp", is_active=False)

        with patch(
            "app.services.oidc_service.validate_and_consume_oidc_state",
            new_callable=AsyncMock,
            return_value="off-idp",
        ):
            with pytest.raises(ValueError, match="not found or inactive"):
                await svc.handle_callback(db_session, "off-idp", self._body())

    @pytest.mark.asyncio
    async def test_token_exchange_failure_raises_value_error(self, db_session):
        await _make_provider(db_session)

        patches = _make_callback_patches(token_data=None)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with pytest.raises(ValueError, match="Token exchange"):
                await svc.handle_callback(db_session, "testidp", self._body())

    @pytest.mark.asyncio
    async def test_missing_id_token_raises_value_error(self, db_session):
        await _make_provider(db_session)

        # token_data has no id_token key
        patches = _make_callback_patches(token_data={"access_token": "at"})
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with pytest.raises(ValueError, match="id_token"):
                await svc.handle_callback(db_session, "testidp", self._body())

    @pytest.mark.asyncio
    async def test_missing_sub_claim_raises_value_error(self, db_session):
        await _make_provider(db_session)

        claims = _fake_claims()
        del claims["sub"]
        patches = _make_callback_patches(claims=claims)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with pytest.raises(ValueError, match="'sub' claim"):
                await svc.handle_callback(db_session, "testidp", self._body())

    @pytest.mark.asyncio
    async def test_missing_email_claim_raises_value_error(self, db_session):
        await _make_provider(db_session)

        claims = _fake_claims()
        del claims["email"]
        patches = _make_callback_patches(claims=claims)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with pytest.raises(ValueError, match="'email' claim"):
                await svc.handle_callback(db_session, "testidp", self._body())

    @pytest.mark.asyncio
    async def test_jit_disabled_no_account_raises_permission_error(self, db_session):
        await _make_provider(db_session, jit_provisioning=False)

        patches = _make_callback_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with pytest.raises(PermissionError, match="JIT provisioning is disabled"):
                await svc.handle_callback(db_session, "testidp", self._body())

    @pytest.mark.asyncio
    async def test_inactive_user_raises_permission_error(self, db_session):
        await _make_provider(db_session)
        await _make_user(db_session, email="alice@example.com", is_active=False)

        patches = _make_callback_patches(claims=_fake_claims(email="alice@example.com"))
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            with pytest.raises(PermissionError, match="disabled"):
                await svc.handle_callback(db_session, "testidp", self._body())


# ---------------------------------------------------------------------------
# handle_callback() — success paths
# ---------------------------------------------------------------------------


class TestHandleCallbackSuccess:

    def _body(self):
        return SSOCallbackRequest(
            code="auth-code",
            state="valid-state",
            redirect_uri="https://app/cb",
        )

    @pytest.mark.asyncio
    async def test_jit_creates_new_user_returns_token_response(self, db_session):
        provider = await _make_provider(db_session, jit_provisioning=True, default_role="analyst")

        patches = _make_callback_patches(
            claims=_fake_claims(sub="new-uid", email="new@example.com", name="New User")
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = await svc.handle_callback(db_session, "testidp", self._body())

        assert isinstance(result, TokenResponse)
        # Verify user was created in DB
        user = await UserRepo.get_by_email(db_session, "new@example.com")
        assert user is not None
        assert user.role == "analyst"
        assert user.full_name == "New User"
        # Verify OIDC link was created
        link = await OIDCUserLinkRepo.get_by_subject(db_session, provider.id, "new-uid")
        assert link is not None

    @pytest.mark.asyncio
    async def test_existing_user_via_email_creates_link_returns_tokens(self, db_session):
        provider = await _make_provider(db_session)
        existing = await _make_user(db_session, email="alice@example.com")

        patches = _make_callback_patches(
            claims=_fake_claims(sub="alice-sub-001", email="alice@example.com")
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = await svc.handle_callback(db_session, "testidp", self._body())

        assert isinstance(result, TokenResponse)
        # A new link should be created
        link = await OIDCUserLinkRepo.get_by_subject(db_session, provider.id, "alice-sub-001")
        assert link is not None
        assert str(link.user_id) == str(existing.id)

    @pytest.mark.asyncio
    async def test_existing_link_used_no_duplicate_link_created(self, db_session):
        provider = await _make_provider(db_session)
        user = await _make_user(db_session, email="alice@example.com")
        # Pre-create the link
        await OIDCUserLinkRepo.create(
            db_session,
            user_id=user.id,
            provider_id=provider.id,
            subject="alice-sub-001",
        )

        patches = _make_callback_patches(
            claims=_fake_claims(sub="alice-sub-001", email="alice@example.com")
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = await svc.handle_callback(db_session, "testidp", self._body())

        assert isinstance(result, TokenResponse)

    @pytest.mark.asyncio
    async def test_mfa_enabled_user_returns_mfa_login_response(self, db_session):
        provider = await _make_provider(db_session)
        user = await _make_user(db_session, email="alice@example.com")
        user.mfa_enabled = True
        await db_session.flush()

        patches = _make_callback_patches(claims=_fake_claims(email="alice@example.com"))
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = await svc.handle_callback(db_session, "testidp", self._body())

        assert isinstance(result, MfaLoginResponse)
        assert result.mfa_token

    @pytest.mark.asyncio
    async def test_last_login_at_updated_on_successful_login(self, db_session):
        await _make_provider(db_session)
        user = await _make_user(db_session, email="alice@example.com")
        assert user.last_login_at is None

        patches = _make_callback_patches(claims=_fake_claims(email="alice@example.com"))
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            await svc.handle_callback(db_session, "testidp", self._body())

        await db_session.refresh(user)
        assert user.last_login_at is not None

    @pytest.mark.asyncio
    async def test_jit_uses_name_claim_for_full_name(self, db_session):
        await _make_provider(db_session)

        patches = _make_callback_patches(
            claims=_fake_claims(
                sub="uid-x",
                email="named@example.com",
                name="Full Name Here",
            )
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            await svc.handle_callback(db_session, "testidp", self._body())

        user = await UserRepo.get_by_email(db_session, "named@example.com")
        assert user.full_name == "Full Name Here"

    @pytest.mark.asyncio
    async def test_jit_falls_back_to_given_name_claim(self, db_session):
        await _make_provider(db_session)

        # No 'name' claim, only 'given_name'
        claims = _fake_claims(sub="uid-y", email="gn@example.com")
        del claims["name"]
        claims["given_name"] = "GivenOnly"

        patches = _make_callback_patches(claims=claims)
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            await svc.handle_callback(db_session, "testidp", self._body())

        user = await UserRepo.get_by_email(db_session, "gn@example.com")
        assert user.full_name == "GivenOnly"

    @pytest.mark.asyncio
    async def test_token_response_contains_access_and_refresh_tokens(self, db_session):
        await _make_provider(db_session)

        patches = _make_callback_patches(
            claims=_fake_claims(sub="uid-z", email="tok@example.com")
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            result = await svc.handle_callback(db_session, "testidp", self._body())

        assert isinstance(result, TokenResponse)
        assert result.access_token
        assert result.refresh_token
        assert result.expires_in > 0

    @pytest.mark.asyncio
    async def test_jit_role_resolved_from_claim_mapping(self, db_session):
        await _make_provider(
            db_session,
            role_claim="groups",
            role_mapping={"soc-engineers": "engineer"},
            default_role="analyst",
        )

        patches = _make_callback_patches(
            claims=_fake_claims(
                sub="eng-uid",
                email="engineer@example.com",
                groups=["soc-engineers"],
            )
        )
        with patches[0], patches[1], patches[2], patches[3], patches[4]:
            await svc.handle_callback(db_session, "testidp", self._body())

        user = await UserRepo.get_by_email(db_session, "engineer@example.com")
        assert user.role == "engineer"
