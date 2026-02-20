"""Alert webhook output — POSTs enriched alerts as JSON to configurable URLs.

Each alert published to mxtac.enriched is serialised as a JSON object and
HTTP POSTed to every configured URL.  Transient failures (connection errors,
timeouts, and 5xx responses) are retried up to ``retry_count`` times with
exponential back-off.  All errors are logged and swallowed so that a webhook
failure never interrupts the rest of the alert pipeline.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Sequence

import httpx

from ..core.logging import get_logger
from ..pipeline.queue import MessageQueue, Topic

logger = get_logger(__name__)

_RETRY_BASE_DELAY = 0.5  # seconds — doubled on each retry


class AlertWebhookSender:
    """Sends enriched alert dicts as JSON POST requests to a set of URLs.

    A single shared :class:`httpx.AsyncClient` is used for all requests so
    that connection pooling is reused across alerts.  Call :meth:`close` during
    application shutdown to release the underlying connection pool.
    """

    def __init__(
        self,
        urls: Sequence[str],
        timeout: int = 5,
        retry_count: int = 3,
    ) -> None:
        self._urls = list(urls)
        self._retry_count = retry_count
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"Content-Type": "application/json"},
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _post_with_retry(self, url: str, payload: str) -> None:
        """POST *payload* to *url*, retrying on transient errors."""
        delay = _RETRY_BASE_DELAY
        for attempt in range(self._retry_count + 1):
            try:
                resp = await self._client.post(url, content=payload)
                if resp.status_code < 500:
                    # 2xx / 3xx / 4xx — treat as final (don't retry client errors)
                    if resp.status_code >= 400:
                        logger.warning(
                            "Webhook POST %s returned %d (non-retryable)",
                            url,
                            resp.status_code,
                        )
                    return
                # 5xx — retryable server error
                logger.warning(
                    "Webhook POST %s returned %d (attempt %d/%d)",
                    url,
                    resp.status_code,
                    attempt + 1,
                    self._retry_count + 1,
                )
            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                logger.warning(
                    "Webhook POST %s failed: %s (attempt %d/%d)",
                    url,
                    exc,
                    attempt + 1,
                    self._retry_count + 1,
                )

            if attempt < self._retry_count:
                await asyncio.sleep(delay)
                delay *= 2  # exponential back-off

        logger.error("Webhook POST %s failed after %d attempts", url, self._retry_count + 1)

    # ------------------------------------------------------------------
    # Public async interface
    # ------------------------------------------------------------------

    async def send(self, alert: dict[str, Any]) -> None:
        """Serialise *alert* as JSON and POST it to all configured URLs.

        Errors are logged and swallowed so that a delivery failure never
        interrupts the rest of the alert pipeline.
        """
        if not self._urls:
            return
        try:
            payload = json.dumps(alert, default=str)
        except Exception:
            logger.exception("AlertWebhookSender serialisation error (non-fatal)")
            return

        tasks = [self._post_with_retry(url, payload) for url in self._urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for url, result in zip(self._urls, results):
            if isinstance(result, Exception):
                logger.exception(
                    "AlertWebhookSender unexpected error for %s: %s", url, result
                )

    async def close(self) -> None:
        """Close the underlying HTTP client and release connection pool resources."""
        try:
            await self._client.aclose()
        except Exception:
            logger.exception("AlertWebhookSender close error")


async def alert_webhook_output(
    queue: MessageQueue,
    urls: Sequence[str],
    timeout: int = 5,
    retry_count: int = 3,
) -> AlertWebhookSender:
    """Subscribe an :class:`AlertWebhookSender` to ``mxtac.enriched``.

    Returns the sender so the caller can close it during shutdown.
    """
    sender = AlertWebhookSender(urls, timeout=timeout, retry_count=retry_count)

    async def _handle(alert: dict[str, Any]) -> None:
        await sender.send(alert)

    await queue.subscribe(Topic.ENRICHED, "alert-webhook-output", _handle)
    logger.info(
        "Alert webhook output subscribed to %s → %d URL(s): %s",
        Topic.ENRICHED,
        len(list(urls)),
        list(urls),
    )
    return sender
