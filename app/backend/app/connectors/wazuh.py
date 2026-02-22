"""
Wazuh connector — polls the Wazuh REST API for new alerts.

Required config.extra keys:
  url: str          — e.g. "https://wazuh.internal:55000"
  username: str     — Wazuh API user (e.g. "wazuh-wui")
  password: str
  verify_ssl: bool  — default True
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncGenerator

import httpx

from ..core.logging import get_logger
from ..pipeline.queue import Topic
from .base import BaseConnector, ConnectorConfig, ConnectorStatus

logger = get_logger(__name__)

DEFAULT_PAGE_SIZE = 100
BACKOFF_BASE = 1.0    # seconds — initial delay after a failure
BACKOFF_MAX  = 60.0   # seconds — maximum backoff delay (feature 6.5)


class WazuhConnector(BaseConnector):
    """Polls Wazuh Manager REST API and publishes raw alerts to mxtac.raw.wazuh."""

    def __init__(
        self,
        config: ConnectorConfig,
        queue,
        *,
        initial_last_fetched_at: datetime | None = None,
        checkpoint_callback: Callable[[datetime], Awaitable[None]] | None = None,
        status_callback: Callable[[str, str | None], Awaitable[None]] | None = None,
    ) -> None:
        super().__init__(config, queue, status_callback=status_callback)
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._last_fetched_at: datetime = (
            initial_last_fetched_at
            if initial_last_fetched_at is not None
            else datetime.now(timezone.utc) - timedelta(minutes=5)
        )
        self._checkpoint_callback = checkpoint_callback
        self._backoff_delay: float = BACKOFF_BASE

    @property
    def topic(self) -> str:
        return Topic.RAW_WAZUH

    # ── Connection ───────────────────────────────────────────────────────────

    async def _connect(self) -> None:
        extra = self.config.extra
        base_url   = extra["url"].rstrip("/")
        username   = extra["username"]
        password   = extra["password"]
        verify_ssl = extra.get("verify_ssl", True)

        # Reuse the existing client on re-auth (e.g. token expiry)
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=base_url,
                verify=verify_ssl,
                timeout=30,
                follow_redirects=True,
            )

        # Authenticate — Wazuh uses Basic Auth → JWT
        resp = await self._client.get(
            "/security/user/authenticate",
            auth=(username, password),
        )
        resp.raise_for_status()
        self._token = resp.json()["data"]["token"]
        logger.info("WazuhConnector authenticated url=%s", base_url)

    # ── Token refresh ─────────────────────────────────────────────────────────

    async def _refresh_token(self) -> None:
        """Invalidate the current token and re-authenticate."""
        logger.warning(
            "WazuhConnector token expired, refreshing name=%s",
            self.config.name,
        )
        self._token = None
        await self._connect()

    # ── Fetch ────────────────────────────────────────────────────────────────

    async def _fetch_events(self) -> AsyncGenerator[dict[str, Any], None]:
        if self._client is None or self._token is None:
            return

        headers = {"Authorization": f"Bearer {self._token}"}
        since   = self._last_fetched_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        offset  = 0

        while True:
            params = {
                "limit":  DEFAULT_PAGE_SIZE,
                "offset": offset,
                "q":      f"timestamp>{since}",
                "sort":   "+timestamp",
            }

            resp = await self._client.get("/alerts", headers=headers, params=params)

            if resp.status_code == 401:
                await self._refresh_token()
                headers = {"Authorization": f"Bearer {self._token}"}
                resp = await self._client.get("/alerts", headers=headers, params=params)

            resp.raise_for_status()

            data   = resp.json()
            alerts = data.get("data", {}).get("affected_items", [])

            for alert in alerts:
                yield alert

            # Pagination
            total_items = data.get("data", {}).get("total_affected_items", 0)
            offset += DEFAULT_PAGE_SIZE
            if offset >= total_items:
                break

        self._last_fetched_at = datetime.now(timezone.utc)
        if self._checkpoint_callback is not None:
            await self._checkpoint_callback(self._last_fetched_at)

    # ── Poll loop (feature 6.5 — exponential backoff) ────────────────────────

    async def _poll_loop(self) -> None:
        """Poll loop with exponential backoff on failure.

        A successful fetch cycle resets the backoff to BACKOFF_BASE.
        A failed cycle sleeps for the current _backoff_delay, then doubles it
        (capped at BACKOFF_MAX), before the next attempt.  The normal
        poll_interval_seconds sleep is only applied after a *successful* cycle.
        """
        while not self._stop_event.is_set():
            try:
                async for event in self._fetch_events():
                    await self.queue.publish(self.topic, event)
                    self.health.events_total += 1
                    self.health.last_event_at = datetime.now(timezone.utc)
                # Success — reset backoff to base
                self._backoff_delay = BACKOFF_BASE
                # Feature 6.6: persist active status to DB after a successful cycle
                await self._update_db_status(ConnectorStatus.ACTIVE.value)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                self.health.errors_total += 1
                self.health.error_message = str(exc)
                logger.error(
                    "WazuhConnector fetch error name=%s err=%s backoff=%.1fs",
                    self.config.name,
                    exc,
                    self._backoff_delay,
                )
                # Feature 6.6: persist error status and message to DB
                await self._update_db_status(ConnectorStatus.ERROR.value, str(exc))
                # Sleep for the current backoff delay before retrying
                try:
                    await asyncio.wait_for(
                        asyncio.shield(self._stop_event.wait()),
                        timeout=self._backoff_delay,
                    )
                except asyncio.TimeoutError:
                    pass
                # Increase backoff for the next failure, capped at maximum
                self._backoff_delay = min(self._backoff_delay * 2, BACKOFF_MAX)
                continue  # skip the normal inter-poll sleep

            # Normal inter-poll sleep (success path only)
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._stop_event.wait()),
                    timeout=self.config.poll_interval_seconds,
                )
            except asyncio.TimeoutError:
                pass

    # ── Cleanup ──────────────────────────────────────────────────────────────

    async def stop(self) -> None:
        await super().stop()
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            self._token = None
        logger.info("WazuhConnector HTTP client closed name=%s", self.config.name)


class WazuhConnectorFactory:
    """Convenience factory from environment/config dict."""

    @staticmethod
    def from_dict(d: dict[str, Any], queue) -> WazuhConnector:
        config = ConnectorConfig(
            name=d.get("name", "wazuh"),
            connector_type="wazuh",
            enabled=d.get("enabled", True),
            poll_interval_seconds=d.get("poll_interval_seconds", 60),
            extra={
                "url":        d["url"],
                "username":   d["username"],
                "password":   d["password"],
                "verify_ssl": d.get("verify_ssl", True),
            },
        )
        return WazuhConnector(config, queue)
