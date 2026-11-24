"""Helpers for the refresh cookie in API tests.

The refresh token is never part of a response body: the API sets it as an
HttpOnly cookie scoped to POST /auth/refresh.
"""

from __future__ import annotations

from http.cookies import Morsel, SimpleCookie

from httpx import Response

from app.core.security import REFRESH_COOKIE_NAME


def refresh_cookie(token: str) -> dict[str, str]:
    """Request headers that present *token* as the refresh cookie."""
    return {"Cookie": f"{REFRESH_COOKIE_NAME}={token}"}


def refresh_cookie_morsel(resp: Response) -> Morsel | None:
    """The refresh cookie a response sets (with its attributes), or None."""
    for header in resp.headers.get_list("set-cookie"):
        jar = SimpleCookie()
        jar.load(header)
        if REFRESH_COOKIE_NAME in jar:
            return jar[REFRESH_COOKIE_NAME]
    return None


def refresh_token_of(resp: Response) -> str | None:
    """The refresh token a response sets; None when it sets none or deletes it."""
    morsel = refresh_cookie_morsel(resp)
    return morsel.value or None if morsel is not None else None
