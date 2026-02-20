"""Security headers middleware — feature 33.2.

Adds security-relevant HTTP response headers to every API response:

  X-Content-Type-Options: nosniff
    Prevents browsers from MIME-sniffing the content type.

  X-Frame-Options: DENY
    Blocks clickjacking by preventing any framing of the response.

  X-XSS-Protection: 0
    Disables legacy browser XSS auditor; modern browsers rely on CSP instead.

  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
    Restricts resource loading to same-origin. Inline styles are allowed for
    API-served HTML (docs, redoc).

  Referrer-Policy: strict-origin-when-cross-origin
    Sends full referrer for same-origin; only the origin for cross-origin HTTPS;
    nothing for cross-origin HTTP.

  Permissions-Policy: camera=(), microphone=(), geolocation=()
    Opts out of powerful browser features that the API does not need.

  Cache-Control: no-store
    Prevents caching of API responses, which may carry sensitive data.

  Strict-Transport-Security: max-age=31536000; includeSubDomains  (production only)
    Instructs browsers to connect via HTTPS only.  Omitted in debug/dev mode
    so that local HTTP development is not broken.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Awaitable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .config import settings

# Headers applied unconditionally to every response.
_STATIC_HEADERS: dict[str, str] = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    ),
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}

# HSTS header — only added in production (DEBUG=False).
_HSTS_HEADER = "Strict-Transport-Security"
_HSTS_VALUE = "max-age=31536000; includeSubDomains"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Append security headers to every outgoing response.

    HSTS is only added when ``settings.debug`` is ``False`` so that local
    HTTP development sessions are not permanently redirected to HTTPS.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)

        for header, value in _STATIC_HEADERS.items():
            response.headers[header] = value

        if not settings.debug:
            response.headers[_HSTS_HEADER] = _HSTS_VALUE

        return response
