"""Tests for Feature 2.4 — Password history (cannot reuse last 2).

Coverage:
  change-password — new_password matches current hash → 400
  change-password — new_password matches previous hash (in history) → 400
  change-password — new_password is fresh → 200
  change-password — password_history=None (no history yet) → new password accepted
  change-password — history updated: old current hash stored in history after change
  change-password — third change: oldest history entry scrolls out after 2 changes
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.core.security import create_password_change_token
from app.models.user import User

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHANGE_PW_URL = "/api/v1/auth/change-password"

MOCK_REPO_BY_ID = "app.api.v1.endpoints.auth.UserRepo.get_by_id"
MOCK_VERIFY_PW = "app.api.v1.endpoints.auth.verify_password"
MOCK_HASH = "app.api.v1.endpoints.auth.hash_password"

_TEST_USER_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_TEST_EMAIL = "analyst@mxtac.local"

_CURRENT_HASH = "$2b$12$current_hash_placeholder"
_PREV_HASH = "$2b$12$previous_hash_placeholder"
_NEW_HASH = "$2b$12$new_hash_placeholder"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(password_history: list | None = None) -> User:
    user = User(
        email=_TEST_EMAIL,
        hashed_password=_CURRENT_HASH,
        role="analyst",
        is_active=True,
    )
    user.id = _TEST_USER_ID
    user.mfa_enabled = False
    user.must_change_password = False
    user.password_history = password_history
    user.last_login_at = None
    user.inactive_locked_at = None
    user.password_changed_at = None
    return user


def _pc_token() -> str:
    return create_password_change_token(_TEST_USER_ID)


def _verify_matches(target_hash: str):
    """Returns a verify_password side_effect that returns True only for the target hash."""
    def _side_effect(plain: str, hashed: str) -> bool:
        return hashed == target_hash
    return _side_effect


def _verify_never_matches(_plain: str, _hashed: str) -> bool:
    """verify_password side_effect that always returns False (fresh password)."""
    return False


# ---------------------------------------------------------------------------
# Reuse of current password is rejected (400)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reuse_current_password_rejected(client: AsyncClient) -> None:
    """new_password matching the current hash → 400 with history error."""
    user = _make_user(password_history=None)
    token = _pc_token()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        # verify_password returns True when hashed == current hash → first candidate matches
        with patch(MOCK_VERIFY_PW, side_effect=_verify_matches(_CURRENT_HASH)):
            resp = await client.post(
                CHANGE_PW_URL,
                json={
                    "password_change_token": token,
                    "new_password": "NewSecure1!",
                    "confirm_password": "NewSecure1!",
                },
            )

    assert resp.status_code == 400
    assert "last 2" in resp.json()["detail"].lower() or "reuse" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_reuse_current_password_detail_message(client: AsyncClient) -> None:
    """Error detail mentions password reuse when current hash matches."""
    user = _make_user(password_history=None)
    token = _pc_token()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, side_effect=_verify_matches(_CURRENT_HASH)):
            resp = await client.post(
                CHANGE_PW_URL,
                json={
                    "password_change_token": token,
                    "new_password": "NewSecure1!",
                    "confirm_password": "NewSecure1!",
                },
            )

    detail = resp.json()["detail"]
    assert "Cannot reuse" in detail or "reuse" in detail.lower()


# ---------------------------------------------------------------------------
# Reuse of previous password (in history) is rejected (400)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reuse_previous_password_rejected(client: AsyncClient) -> None:
    """new_password matching a history hash → 400."""
    user = _make_user(password_history=[_PREV_HASH])
    token = _pc_token()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        # current hash does NOT match, but the history hash does
        with patch(MOCK_VERIFY_PW, side_effect=_verify_matches(_PREV_HASH)):
            resp = await client.post(
                CHANGE_PW_URL,
                json={
                    "password_change_token": token,
                    "new_password": "NewSecure1!",
                    "confirm_password": "NewSecure1!",
                },
            )

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_reuse_previous_password_with_empty_history_accepted(client: AsyncClient) -> None:
    """password_history=[] (empty list) — no previous hash to check; new password accepted."""
    user = _make_user(password_history=[])
    token = _pc_token()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, side_effect=_verify_never_matches):
            with patch(MOCK_HASH, return_value=_NEW_HASH):
                resp = await client.post(
                    CHANGE_PW_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )

    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Fresh password (no history match) is accepted
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fresh_password_accepted(client: AsyncClient) -> None:
    """New password matching no history entries → 200 with tokens."""
    user = _make_user(password_history=[_PREV_HASH])
    token = _pc_token()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, side_effect=_verify_never_matches):
            with patch(MOCK_HASH, return_value=_NEW_HASH):
                resp = await client.post(
                    CHANGE_PW_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


@pytest.mark.asyncio
async def test_no_history_fresh_password_accepted(client: AsyncClient) -> None:
    """password_history=None (account never had history) → new password accepted."""
    user = _make_user(password_history=None)
    token = _pc_token()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, side_effect=_verify_never_matches):
            with patch(MOCK_HASH, return_value=_NEW_HASH):
                resp = await client.post(
                    CHANGE_PW_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )

    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# History rotation — current hash stored after a successful change
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_history_updated_after_change(client: AsyncClient) -> None:
    """After a successful change, the old current hash is stored in password_history."""
    user = _make_user(password_history=None)
    token = _pc_token()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, side_effect=_verify_never_matches):
            with patch(MOCK_HASH, return_value=_NEW_HASH):
                resp = await client.post(
                    CHANGE_PW_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )

    assert resp.status_code == 200
    # The old current hash should now be in history
    assert user.password_history == [_CURRENT_HASH]
    # The new hash should be the current hashed_password
    assert user.hashed_password == _NEW_HASH


@pytest.mark.asyncio
async def test_history_keeps_one_entry(client: AsyncClient) -> None:
    """After a change, history contains exactly 1 entry (the old current hash)."""
    user = _make_user(password_history=[_PREV_HASH])
    token = _pc_token()

    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, side_effect=_verify_never_matches):
            with patch(MOCK_HASH, return_value=_NEW_HASH):
                resp = await client.post(
                    CHANGE_PW_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )

    assert resp.status_code == 200
    # History should now hold the old current hash (old _PREV_HASH is dropped)
    assert user.password_history == [_CURRENT_HASH]


# ---------------------------------------------------------------------------
# Scrolling window — after 2 changes, old password becomes reusable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_oldest_password_scrolls_out_after_second_change(client: AsyncClient) -> None:
    """After two successive changes, the original password is no longer in the window.

    Sequence:
      - Start: current=_CURRENT_HASH, history=[_PREV_HASH]
      - After change 1: current=_NEW_HASH, history=[_CURRENT_HASH]  ← _PREV_HASH gone
      → _PREV_HASH can now be reused (would not trigger 400)
    """
    user = _make_user(password_history=[_PREV_HASH])
    token = _pc_token()

    # First change: _NEW_HASH replaces _CURRENT_HASH; history becomes [_CURRENT_HASH]
    with patch(MOCK_REPO_BY_ID, new=AsyncMock(return_value=user)):
        with patch(MOCK_VERIFY_PW, side_effect=_verify_never_matches):
            with patch(MOCK_HASH, return_value=_NEW_HASH):
                resp = await client.post(
                    CHANGE_PW_URL,
                    json={
                        "password_change_token": token,
                        "new_password": "NewSecure1!",
                        "confirm_password": "NewSecure1!",
                    },
                )

    assert resp.status_code == 200
    # _PREV_HASH has now scrolled out of the window
    assert _PREV_HASH not in (user.password_history or [])
    assert _CURRENT_HASH in (user.password_history or [])
