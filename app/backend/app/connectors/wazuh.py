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
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncGenerator

import httpx

from ..core.logging import get_logger
from ..pipeline.queue import Topic
from .base import BaseConnector, ConnectorConfig

logger = get_logger(__name__)

DEFAULT_PAGE_SIZE = 100


class WazuhConnector(BaseConnector):
    """Polls Wazuh Manager REST API and publishes raw alerts to mxtac.raw.wazuh."""

    def __init__(self, config: ConnectorConfig, queue) -> None:
        super().__init__(config, queue)
        self._client: httpx.AsyncClient | None = None
        self._token: str | None = None
        self._last_fetched_at: datetime = datetime.now(timezone.utc) - timedelta(minutes=5)

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
                # Token expired — re-authenticate and retry once
                await self._connect()
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
