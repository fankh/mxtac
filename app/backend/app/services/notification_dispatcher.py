"""Notification dispatcher — routes enriched alerts to configured notification channels.

Channels are loaded from the NotificationChannel table and cached for 60 seconds
to avoid hammering the database on every alert.

Rate limiting: max 1 notification per (channel_id, rule_id, host) per 5 minutes.
All send errors are logged and swallowed — a delivery failure never interrupts the pipeline.

Supported channel types:
  email   — SMTP via thread-pool executor (smtplib)
  slack   — POST to Slack incoming webhook URL with formatted attachment
  webhook — POST alert JSON to configured URL (configurable method, headers, auth)
  msteams — POST adaptive card to MS Teams webhook URL
"""

from __future__ import annotations

import asyncio
import email.mime.multipart
import email.mime.text
import json
import smtplib
import time
from typing import TYPE_CHECKING, Any

import httpx

from ..core.logging import get_logger

if TYPE_CHECKING:
    from ..models.notification import NotificationChannel

logger = get_logger(__name__)

# Severity ordering — higher int = more severe
_SEVERITY_ORDER: dict[str, int] = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Channel configuration cache TTL (seconds)
_CACHE_TTL = 60.0

# Rate limiting window (seconds) — 5 minutes
_RATE_LIMIT_WINDOW = 300.0

# Maximum entries in the in-memory rate cache before pruning
_RATE_CACHE_MAX = 10_000


def _severity_color(level: str) -> str:
    """Return a hex color for the given severity level (used in Slack attachments)."""
    return {
        "critical": "#8B0000",
        "high": "#FF4500",
        "medium": "#FFA500",
        "low": "#3AA3E3",
    }.get(level.lower(), "#808080")


class NotificationDispatcher:
    """Dispatches enriched alerts to all enabled, matching notification channels.

    Instantiate once at startup, pass to AlertManager, and call :meth:`close`
    during shutdown to release the underlying HTTP connection pool.
    """

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            headers={"Content-Type": "application/json"},
        )
        # In-memory rate-limit cache: key -> monotonic timestamp of last send
        self._rate_cache: dict[str, float] = {}
        self._rate_lock = asyncio.Lock()
        # Channel cache (refreshed every _CACHE_TTL seconds)
        self._channels_cache: list[NotificationChannel] | None = None
        self._channels_cache_at: float = 0.0

    # ------------------------------------------------------------------
    # Channel loading (DB-backed, with TTL cache)
    # ------------------------------------------------------------------

    async def load_channels(self) -> list[NotificationChannel]:
        """Return enabled channels from DB, refreshing at most once per _CACHE_TTL seconds."""
        now = time.monotonic()
        if (
            self._channels_cache is not None
            and (now - self._channels_cache_at) < _CACHE_TTL
        ):
            return self._channels_cache

        try:
            from ..core.database import AsyncSessionLocal
            from ..repositories.notification_channel_repo import NotificationChannelRepo

            async with AsyncSessionLocal() as session:
                channels = await NotificationChannelRepo.list_enabled(session)
            self._channels_cache = channels
            self._channels_cache_at = now
            logger.debug(
                "NotificationDispatcher: loaded %d enabled channel(s) from DB", len(channels)
            )
            return channels
        except Exception:
            logger.exception("NotificationDispatcher: failed to load channels from DB")
            # Return stale cache on error rather than failing hard
            return self._channels_cache or []

    # ------------------------------------------------------------------
    # Rate limiting (in-memory, per channel+rule+host)
    # ------------------------------------------------------------------

    async def _is_rate_limited(
        self, channel: NotificationChannel, alert: dict[str, Any]
    ) -> bool:
        """Return True if this (channel, rule_id, host) was already notified within the window.

        Also records the current send timestamp so subsequent calls within the
        window are correctly suppressed.
        """
        key = f"{channel.id}:{alert.get('rule_id', '')}:{alert.get('host', '')}"
        now = time.monotonic()

        async with self._rate_lock:
            last_sent = self._rate_cache.get(key)
            if last_sent is not None and (now - last_sent) < _RATE_LIMIT_WINDOW:
                return True

            # Not rate-limited — record this dispatch timestamp
            self._rate_cache[key] = now

            # Prune stale entries to prevent unbounded memory growth
            if len(self._rate_cache) > _RATE_CACHE_MAX:
                cutoff = now - _RATE_LIMIT_WINDOW
                self._rate_cache = {
                    k: v for k, v in self._rate_cache.items() if v > cutoff
                }

        return False

    # ------------------------------------------------------------------
    # Public dispatch interface
    # ------------------------------------------------------------------

    async def dispatch(self, alert: dict[str, Any]) -> None:
        """Send alert to all enabled channels whose min_severity threshold is met.

        Errors are logged and swallowed — a delivery failure never interrupts
        the alert pipeline.
        """
        try:
            channels = await self.load_channels()
        except Exception:
            logger.exception("NotificationDispatcher: load_channels failed (non-fatal)")
            return

        if not channels:
            return

        alert_severity = alert.get("level", "low")
        alert_rank = _SEVERITY_ORDER.get(alert_severity, 0)

        tasks: list[Any] = []
        dispatching_channels: list[NotificationChannel] = []

        for channel in channels:
            min_rank = _SEVERITY_ORDER.get(channel.min_severity, 0)
            if alert_rank < min_rank:
                logger.debug(
                    "NotificationDispatcher: skipping channel=%r (alert=%s < min=%s)",
                    channel.name,
                    alert_severity,
                    channel.min_severity,
                )
                continue

            if await self._is_rate_limited(channel, alert):
                logger.debug(
                    "NotificationDispatcher: rate-limited channel=%r rule_id=%s host=%s",
                    channel.name,
                    alert.get("rule_id"),
                    alert.get("host"),
                )
                continue

            tasks.append(self._dispatch_one(channel, alert))
            dispatching_channels.append(channel)

        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for channel, result in zip(dispatching_channels, results):
            if isinstance(result, Exception):
                logger.error(
                    "NotificationDispatcher: unexpected error for channel=%r: %s",
                    channel.name,
                    result,
                )

    async def _dispatch_one(
        self, channel: NotificationChannel, alert: dict[str, Any]
    ) -> None:
        """Parse channel config and route to the appropriate send method."""
        try:
            config: dict[str, Any] = json.loads(channel.config_json or "{}")
        except json.JSONDecodeError:
            logger.error(
                "NotificationDispatcher: invalid config_json for channel=%r id=%d",
                channel.name,
                channel.id,
            )
            return

        if channel.channel_type == "email":
            await self._send_email(config, alert)
        elif channel.channel_type == "slack":
            await self._send_slack(config, alert)
        elif channel.channel_type == "webhook":
            await self._send_webhook(config, alert)
        elif channel.channel_type == "msteams":
            await self._send_msteams(config, alert)
        else:
            logger.warning(
                "NotificationDispatcher: unknown channel_type=%r for channel=%r",
                channel.channel_type,
                channel.name,
            )

    # ------------------------------------------------------------------
    # Channel-specific send methods
    # ------------------------------------------------------------------

    async def _send_email(self, config: dict[str, Any], alert: dict[str, Any]) -> None:
        """Send alert via SMTP (thread-pool executor wrapping smtplib)."""
        smtp_host = config.get("smtp_host", "localhost")
        smtp_port = int(config.get("smtp_port", 587))
        from_addr = config.get("from_address", "mxtac@localhost")
        to_addrs: list[str] = config.get("to_addresses", [])
        use_tls = bool(config.get("use_tls", False))
        username = str(config.get("username", ""))
        password = str(config.get("password", ""))

        if not to_addrs:
            logger.warning("NotificationDispatcher: email channel missing to_addresses")
            return

        def _build_message() -> str:
            level = alert.get("level", "unknown").upper()
            host = alert.get("host", "unknown")
            title = alert.get("rule_title", alert.get("rule_id", "Unknown Rule"))
            score = alert.get("score", 0)

            subject = f"[MxTac Alert] [{level}] {title} — {host} (score {score})"
            msg = email.mime.multipart.MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = from_addr
            msg["To"] = ", ".join(to_addrs)
            body = json.dumps(alert, indent=2, default=str)
            msg.attach(email.mime.text.MIMEText(body, "plain", "utf-8"))
            return msg.as_string()

        def _send_sync() -> None:
            raw = _build_message()
            if use_tls:
                smtp: smtplib.SMTP = smtplib.SMTP_SSL(smtp_host, smtp_port)
            else:
                smtp = smtplib.SMTP(smtp_host, smtp_port)
            with smtp:
                if not use_tls:
                    smtp.starttls()
                if username:
                    smtp.login(username, password)
                smtp.sendmail(from_addr, to_addrs, raw)

        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _send_sync)
        logger.info(
            "NotificationDispatcher: email sent to=%s rule_id=%s",
            to_addrs,
            alert.get("rule_id"),
        )

    async def _send_slack(self, config: dict[str, Any], alert: dict[str, Any]) -> None:
        """POST a formatted message to a Slack incoming webhook URL."""
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            logger.warning("NotificationDispatcher: Slack channel missing webhook_url")
            return

        channel_name = config.get("channel", "#mxtac-alerts")
        username = config.get("username", "MxTac")

        level = alert.get("level", "unknown").upper()
        host = alert.get("host", "unknown")
        title = alert.get("rule_title", alert.get("rule_id", "Unknown Rule"))
        score = alert.get("score", 0)
        technique_ids = ", ".join(alert.get("technique_ids") or [])

        payload = {
            "channel": channel_name,
            "username": username,
            "text": f":rotating_light: *[{level}] {title}*",
            "attachments": [
                {
                    "color": _severity_color(alert.get("level", "low")),
                    "fields": [
                        {"title": "Host", "value": host, "short": True},
                        {"title": "Score", "value": str(score), "short": True},
                        {
                            "title": "Techniques",
                            "value": technique_ids or "N/A",
                            "short": False,
                        },
                        {
                            "title": "Time",
                            "value": alert.get("time", ""),
                            "short": True,
                        },
                    ],
                }
            ],
        }

        resp = await self._client.post(
            webhook_url, content=json.dumps(payload, default=str)
        )
        if resp.status_code >= 400:
            logger.warning(
                "NotificationDispatcher: Slack returned %d rule_id=%s",
                resp.status_code,
                alert.get("rule_id"),
            )
        else:
            logger.info(
                "NotificationDispatcher: Slack notification sent rule_id=%s",
                alert.get("rule_id"),
            )

    async def _send_webhook(
        self, config: dict[str, Any], alert: dict[str, Any]
    ) -> None:
        """POST alert JSON to a generic webhook endpoint."""
        url = config.get("url", "")
        if not url:
            logger.warning("NotificationDispatcher: webhook channel missing url")
            return

        method = config.get("method", "POST").upper()
        extra_headers: dict[str, str] = config.get("headers", {})
        auth_token = config.get("auth_token", "")

        headers = {"Content-Type": "application/json"}
        headers.update(extra_headers)
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        payload = json.dumps(alert, default=str)
        resp = await self._client.request(method, url, content=payload, headers=headers)

        if resp.status_code >= 400:
            logger.warning(
                "NotificationDispatcher: webhook returned %d rule_id=%s url=%s",
                resp.status_code,
                alert.get("rule_id"),
                url,
            )
        else:
            logger.info(
                "NotificationDispatcher: webhook notification sent rule_id=%s url=%s",
                alert.get("rule_id"),
                url,
            )

    async def _send_msteams(
        self, config: dict[str, Any], alert: dict[str, Any]
    ) -> None:
        """POST an adaptive card to a Microsoft Teams incoming webhook."""
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            logger.warning("NotificationDispatcher: MSTeams channel missing webhook_url")
            return

        level = alert.get("level", "unknown").upper()
        host = alert.get("host", "unknown")
        title = alert.get("rule_title", alert.get("rule_id", "Unknown Rule"))
        score = alert.get("score", 0)
        technique_ids = ", ".join(alert.get("technique_ids") or [])

        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": f"[{level}] MxTac Alert: {title}",
                                "weight": "Bolder",
                                "size": "Medium",
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Host", "value": host},
                                    {"title": "Score", "value": str(score)},
                                    {
                                        "title": "Techniques",
                                        "value": technique_ids or "N/A",
                                    },
                                    {
                                        "title": "Time",
                                        "value": alert.get("time", ""),
                                    },
                                ],
                            },
                        ],
                    },
                }
            ],
        }

        resp = await self._client.post(
            webhook_url, content=json.dumps(card, default=str)
        )
        if resp.status_code >= 400:
            logger.warning(
                "NotificationDispatcher: MSTeams returned %d rule_id=%s",
                resp.status_code,
                alert.get("rule_id"),
            )
        else:
            logger.info(
                "NotificationDispatcher: MSTeams notification sent rule_id=%s",
                alert.get("rule_id"),
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        """Close the underlying HTTP client and release connection pool resources."""
        try:
            await self._client.aclose()
        except Exception:
            logger.exception("NotificationDispatcher: close error")
