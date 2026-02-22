"""Notification dispatcher — routes enriched alerts to configured notification channels.

Channels are loaded from the NotificationChannel table and cached for 60 seconds
to avoid hammering the database on every alert.

Rate limiting: max 1 notification per (channel_id, rule_id, host) per 5 minutes.
All send errors are logged and swallowed — a delivery failure never interrupts the pipeline.

Supported channel types:
  email   — async SMTP via aiosmtplib (TLS and STARTTLS supported)
  slack   — POST to Slack incoming webhook URL with formatted attachment
  webhook — POST alert JSON to configured URL (configurable method, headers, auth)
  msteams — POST adaptive card to MS Teams webhook URL
"""

from __future__ import annotations

import asyncio
import email.mime.multipart
import email.mime.text
import json
import re
import time
from typing import TYPE_CHECKING, Any

import aiosmtplib

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
    """Return a hex color for the given severity level (used in Slack attachment sidebar)."""
    return {
        "critical": "#CC0000",  # red
        "high": "#FF8C00",      # orange
        "medium": "#FFD700",    # yellow
        "low": "#808080",       # gray
    }.get(level.lower(), "#808080")


# Severity emojis for Slack Block Kit header
_SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "⚪",
}

# Valid routing rule fields and operators
_RULE_FIELDS = {"severity", "tactic", "technique_id", "host", "rule_name"}
_RULE_OPERATORS = {"eq", "ne", "in", "contains", "regex"}


def _get_alert_value(field: str, alert: dict[str, Any]) -> list[str]:
    """Return alert field value(s) as a list of lower-cased strings.

    Multi-value fields (tactic, technique_id) return a list.
    Single-value fields return a one-element list.
    """
    if field == "severity":
        return [(alert.get("level") or "").lower()]
    if field == "tactic":
        return [(t or "").lower() for t in (alert.get("tactic_ids") or [])]
    if field == "technique_id":
        # Technique IDs are conventionally upper-cased (T1059) but normalise both sides
        return [(t or "").upper() for t in (alert.get("technique_ids") or [])]
    if field == "host":
        return [(alert.get("host") or "").lower()]
    if field == "rule_name":
        name = alert.get("rule_title") or alert.get("rule_id") or ""
        return [name.lower()]
    return []


def _apply_operator(operator: str, vals: list[str], rule_val: Any) -> bool:
    """Evaluate *operator* against the alert field values (OR across list elements).

    For ``ne``: returns True only if the rule_val matches NONE of the elements
    (i.e. the alert has no element equal to rule_val).
    For all other operators: returns True if ANY element satisfies the condition.
    """
    if operator == "eq":
        rv = str(rule_val).lower()
        # technique_id values are upper-cased — normalise rule_val the same way
        return any(v == rv or v == str(rule_val).upper() for v in vals)
    if operator == "ne":
        rv = str(rule_val).lower()
        return all(v != rv and v != str(rule_val).upper() for v in vals)
    if operator == "in":
        if not isinstance(rule_val, list):
            return False
        rule_set_lower = {str(r).lower() for r in rule_val}
        rule_set_upper = {str(r).upper() for r in rule_val}
        return any(v in rule_set_lower or v in rule_set_upper for v in vals)
    if operator == "contains":
        rv = str(rule_val).lower()
        return any(rv in v for v in vals)
    if operator == "regex":
        try:
            pattern = re.compile(str(rule_val), re.IGNORECASE)
            return any(bool(pattern.search(v)) for v in vals)
        except re.error:
            return False
    return False


def _matches_routing_rules(rules: list[dict[str, Any]], alert: dict[str, Any]) -> bool:
    """Return True if at least one routing rule matches the alert (OR logic).

    An empty rule list means "match everything" — no routing filter applied.
    Unknown fields or operators are silently skipped (non-matching).
    """
    if not rules:
        return True

    for rule in rules:
        field = rule.get("field", "")
        operator = rule.get("operator", "")
        value = rule.get("value")

        if field not in _RULE_FIELDS or operator not in _RULE_OPERATORS:
            continue  # skip malformed rules

        alert_vals = _get_alert_value(field, alert)
        if not alert_vals:
            continue

        if _apply_operator(operator, alert_vals, value):
            return True

    return False


def _build_email_html(
    *,
    title: str,
    severity: str,
    host: str,
    tactic: str,
    technique: str,
    timestamp: str,
) -> str:
    """Build an HTML email body for an alert notification."""
    sev_lower = severity.lower()
    sev_colors = {
        "critical": "#8B0000",
        "high": "#FF4500",
        "medium": "#FFA500",
        "low": "#3AA3E3",
    }
    sev_color = sev_colors.get(sev_lower, "#808080")

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{ font-family: Arial, sans-serif; background: #f9f9f9; padding: 20px; }}
  .card {{ background: #fff; border-radius: 6px; padding: 24px; max-width: 600px;
           box-shadow: 0 1px 4px rgba(0,0,0,.12); }}
  h2 {{ margin: 0 0 16px; color: #222; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ padding: 8px 12px; text-align: left; border: 1px solid #e0e0e0; }}
  th {{ background: #f2f2f2; color: #555; font-weight: 600; width: 35%; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
            color: #fff; font-weight: bold; background: {sev_color}; }}
  .footer {{ margin-top: 16px; font-size: 11px; color: #999; }}
</style>
</head>
<body>
<div class="card">
  <h2>MxTac Security Alert</h2>
  <table>
    <tr><th>Alert Title</th><td>{title}</td></tr>
    <tr><th>Severity</th><td><span class="badge">{severity}</span></td></tr>
    <tr><th>Host</th><td>{host}</td></tr>
    <tr><th>Tactic</th><td>{tactic}</td></tr>
    <tr><th>Technique</th><td>{technique}</td></tr>
    <tr><th>Timestamp</th><td>{timestamp}</td></tr>
  </table>
  <p class="footer">Sent by MxTac — MITRE ATT&amp;CK Detection Platform</p>
</div>
</body>
</html>"""


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

            # Evaluate routing rules — if non-empty, at least one must match
            try:
                rules: list[dict] = json.loads(channel.routing_rules or "[]")
            except (json.JSONDecodeError, AttributeError):
                rules = []
            if not _matches_routing_rules(rules, alert):
                logger.debug(
                    "NotificationDispatcher: routing rules not matched channel=%r rule_id=%s",
                    channel.name,
                    alert.get("rule_id"),
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
        """Send alert via aiosmtplib (async SMTP with TLS/STARTTLS support).

        Channel config keys (all optional — fall back to global settings):
          smtp_host       SMTP server hostname (default: localhost)
          smtp_port       SMTP server port (default: 587)
          from_address    Envelope From address
          to_addresses    List of recipient addresses (required — skipped if empty)
          use_tls         True → implicit TLS (port 465); False → STARTTLS (port 587)
          username        SMTP auth username (omit for unauthenticated relay)
          password        SMTP auth password
        """
        from ..core.config import settings  # noqa: PLC0415

        smtp_host = config.get("smtp_host") or settings.smtp_host
        smtp_port = int(config.get("smtp_port") or settings.smtp_port)
        from_addr = config.get("from_address") or settings.smtp_from_address
        to_addrs: list[str] = config.get("to_addresses") or []
        use_tls = bool(config.get("use_tls", False))
        username = str(config.get("username") or settings.smtp_username)
        password = str(config.get("password") or settings.smtp_password)

        if not to_addrs:
            logger.warning("NotificationDispatcher: email channel missing to_addresses")
            return

        severity = (alert.get("level") or "unknown").upper()
        title = alert.get("rule_title") or alert.get("rule_id") or "Unknown Rule"
        host = alert.get("host") or "unknown"
        tactic = ", ".join(alert.get("tactic_ids") or []) or "N/A"
        technique = ", ".join(alert.get("technique_ids") or []) or "N/A"
        timestamp = alert.get("time") or ""

        subject = f"[MxTac {severity}] {title} on {host}"

        html_body = _build_email_html(
            title=title,
            severity=severity,
            host=host,
            tactic=tactic,
            technique=technique,
            timestamp=timestamp,
        )

        msg = email.mime.multipart.MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)
        msg.attach(email.mime.text.MIMEText(html_body, "html", "utf-8"))

        # use_tls=True  → implicit TLS (SMTPS, typically port 465)
        # use_tls=False → STARTTLS upgrade (typically port 587)
        await aiosmtplib.send(
            msg,
            hostname=smtp_host,
            port=smtp_port,
            use_tls=use_tls,
            start_tls=(not use_tls),
            username=username or None,
            password=password or None,
        )
        logger.info(
            "NotificationDispatcher: email sent to=%s rule_id=%s",
            to_addrs,
            alert.get("rule_id"),
        )

    async def _send_slack(self, config: dict[str, Any], alert: dict[str, Any]) -> None:
        """POST a Block Kit message to a Slack incoming webhook URL.

        Channel config keys:
          webhook_url   Slack incoming webhook URL (required)
          channel       Override the webhook's default channel (e.g. "#security-ops")
          username      Override the bot display name (e.g. "MxTac-Bot")
        """
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            logger.warning("NotificationDispatcher: Slack channel missing webhook_url")
            return

        level = (alert.get("level") or "low").lower()
        level_upper = level.upper()
        emoji = _SEVERITY_EMOJI.get(level, "⚪")

        title = alert.get("rule_title") or alert.get("rule_id") or "Unknown Rule"
        host = alert.get("host") or "unknown"
        tactic = ", ".join(alert.get("tactic_ids") or []) or "N/A"
        technique = ", ".join(alert.get("technique_ids") or []) or "N/A"
        timestamp = alert.get("time") or ""
        score = alert.get("score", 0)

        payload: dict[str, Any] = {
            # Fallback text shown in push notifications / thread previews
            "text": f"{emoji} *[{level_upper}] {title}*",
            "attachments": [
                {
                    "color": _severity_color(level),
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji} {title}",
                                "emoji": True,
                            },
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*Host:*\n{host}"},
                                {"type": "mrkdwn", "text": f"*Tactic:*\n{tactic}"},
                                {"type": "mrkdwn", "text": f"*Technique:*\n{technique}"},
                                {"type": "mrkdwn", "text": f"*Rule:*\n{title}"},
                            ],
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Time:* {timestamp}  |  *Score:* {score}",
                                }
                            ],
                        },
                    ],
                }
            ],
        }

        # Apply optional channel / username overrides from the channel config
        if channel := config.get("channel"):
            payload["channel"] = channel
        if username := config.get("username"):
            payload["username"] = username

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
