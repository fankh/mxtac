"""HTTP request access log middleware — feature 21.11.

Logs one structured INFO record per HTTP request:

  {"method":"GET","path":"/api/v1/rules","status":200,"latency_ms":4.71}

The record is emitted through the ``mxtac.access`` logger so operators can
route or filter access logs independently from application logs.

High-frequency internal probe paths (/health, /ready, /metrics) are skipped
to keep the access log signal-to-noise ratio high in production.
"""

import time
from collections.abc import Callable
from typing import Awaitable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from .logging import get_logger

_logger = get_logger("mxtac.access")

# Paths excluded from access logging (ops/probe traffic)
_SKIP_PATHS: frozenset[str] = frozenset({"/health", "/ready", "/metrics"})


class AccessLogMiddleware(BaseHTTPMiddleware):
    """Emit one structured INFO log record per HTTP request.

    Fields logged:
      method      — HTTP verb (GET, POST, …)
      path        — URL path (without query string)
      status      — HTTP response status code
      latency_ms  — wall-clock milliseconds from first byte received to
                    last byte of response headers sent, rounded to 2 dp
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        start = time.perf_counter()
        response = await call_next(request)
        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        _logger.info(
            '{"method":"%s","path":"%s","status":%d,"latency_ms":%.2f}',
            request.method,
            request.url.path,
            response.status_code,
            latency_ms,
        )
        return response
