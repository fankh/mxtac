"""WS /api/v1/ws/alerts requires a valid access token in ``?token=``.

Invalid connections are closed during the handshake with code 1008 (policy
violation); the server never accepts them.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import app.api.v1.endpoints.websocket as ws_module
from app.api.v1.endpoints.websocket import manager
from app.core.security import (
    create_access_token,
    create_mfa_token,
    create_password_change_token,
    create_refresh_token,
)
from app.main import app
from app.models import Base
from app.models.user import User

WS_URL = "/api/v1/ws/alerts"
EMAIL = "casey@mxtac.local"
USER_ID = "4c1f6a0e-2b7d-4e3a-9f58-7d1c2e3b4a06"


@pytest.fixture(autouse=True)
def _token_only_principals():
    """Override the conftest shim: production behaviour (user must exist)."""
    yield


@pytest.fixture(autouse=True)
def _no_valkey():
    """No Valkey in unit tests: skip the revocation lookup (it would time out)."""
    with patch("app.core.security.is_token_blacklisted", new=AsyncMock(return_value=False)):
        yield


@pytest.fixture
def ws_client(tmp_path) -> Iterator[tuple[TestClient, async_sessionmaker]]:
    """TestClient whose WebSocket auth reads users from a temporary SQLite file.

    The app's startup / shutdown hooks are not run (no ``with`` block), and the
    Valkey subscriber and the ping loop are stubbed out.
    """
    url = f"sqlite+aiosqlite:///{(tmp_path / 'ws.db').as_posix()}"
    engine = create_async_engine(url, poolclass=StaticPool)
    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    sync_engine = create_engine(url.replace("+aiosqlite", ""))
    Base.metadata.create_all(sync_engine)
    with sync_engine.begin() as conn:
        conn.execute(
            User.__table__.insert().values(
                id=USER_ID, email=EMAIL, hashed_password="not-used",
                role="viewer", is_active=True, mfa_enabled=False, must_change_password=False,
            )
        )

    manager._connections.clear()
    with (
        patch.object(ws_module, "AsyncSessionLocal", session_factory),
        patch.object(manager, "_ensure_subscriber", new=AsyncMock()),
        patch.object(ws_module, "_ping_loop", new=AsyncMock()),
    ):
        yield TestClient(app), sync_engine
    manager._connections.clear()
    sync_engine.dispose()


def _set_user(sync_engine, **values) -> None:
    with sync_engine.begin() as conn:
        conn.execute(User.__table__.update().where(User.email == EMAIL).values(**values))


def _access_token(**overrides) -> str:
    return create_access_token({"sub": EMAIL, "role": "viewer", **overrides})


def _assert_rejected(client: TestClient, url: str) -> None:
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(url):
            pass
    assert excinfo.value.code == 1008
    assert not manager._connections


def test_valid_access_token_is_accepted(ws_client) -> None:
    client, _ = ws_client
    with client.websocket_connect(f"{WS_URL}?token={_access_token()}") as ws:
        assert ws.receive_json()["type"] == "connected"


def test_missing_token_is_rejected(ws_client) -> None:
    client, _ = ws_client
    _assert_rejected(client, WS_URL)
    _assert_rejected(client, f"{WS_URL}?token=")


def test_garbage_token_is_rejected(ws_client) -> None:
    client, _ = ws_client
    _assert_rejected(client, f"{WS_URL}?token=not-a-jwt")


def test_expired_token_is_rejected(ws_client) -> None:
    client, _ = ws_client
    token = create_access_token({"sub": EMAIL}, expires_delta=timedelta(seconds=-5))
    _assert_rejected(client, f"{WS_URL}?token={token}")


@pytest.mark.parametrize(
    "token_factory",
    [
        lambda: create_refresh_token({"sub": EMAIL}),
        lambda: create_mfa_token(USER_ID),
        lambda: create_password_change_token(USER_ID),
    ],
    ids=["refresh", "mfa", "password_change"],
)
def test_non_access_token_is_rejected(ws_client, token_factory) -> None:
    client, _ = ws_client
    _assert_rejected(client, f"{WS_URL}?token={token_factory()}")


def test_revoked_token_is_rejected(ws_client) -> None:
    client, _ = ws_client
    with patch("app.core.security.is_token_blacklisted", new=AsyncMock(return_value=True)):
        _assert_rejected(client, f"{WS_URL}?token={_access_token()}")


def test_deactivated_user_is_rejected(ws_client) -> None:
    client, sync_engine = ws_client
    _set_user(sync_engine, is_active=False)
    _assert_rejected(client, f"{WS_URL}?token={_access_token()}")


def test_token_of_unknown_user_is_rejected(ws_client) -> None:
    client, _ = ws_client
    token = create_access_token({"sub": "ghost@mxtac.local", "role": "admin"})
    _assert_rejected(client, f"{WS_URL}?token={token}")


def test_role_without_detections_read_is_rejected(ws_client) -> None:
    """The permission check uses the role stored in the database."""
    client, sync_engine = ws_client
    _set_user(sync_engine, role="auditor")          # not in the permission matrix
    _assert_rejected(client, f"{WS_URL}?token={_access_token(role='admin')}")


def test_authorization_header_is_not_an_alternative_to_the_query_parameter(ws_client) -> None:
    """Browsers cannot set headers on a WebSocket; the contract is ?token= only."""
    client, _ = ws_client
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect(
            WS_URL, headers={"Authorization": f"Bearer {_access_token()}"}
        ):
            pass
    assert excinfo.value.code == 1008
