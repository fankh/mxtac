"""Alert email output — sends high-severity enriched alerts via SMTP.

Only alerts whose severity is at or above the configured minimum level
(default: ``high``) are forwarded.  This avoids email noise from low-priority
detections while ensuring critical and high alerts always reach responders.

Severity levels (ascending):
    informational → low → medium → high → critical

Blocking SMTP I/O runs in the default thread-pool executor to avoid stalling
the asyncio event loop.  All errors are logged and swallowed so that an email
delivery failure never interrupts the rest of the alert pipeline.
"""

from __future__ import annotations

import asyncio
import email.mime.multipart
import email.mime.text
import json
import smtplib
import threading
from typing import Any, Sequence

from ..core.logging import get_logger
from ..pipeline.queue import MessageQueue, Topic

logger = get_logger(__name__)

# Severity level ordering — higher int = more severe
_SEVERITY_ORDER: dict[str, int] = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}
_DEFAULT_MIN_LEVEL = "high"


def _severity_rank(level: str) -> int:
    return _SEVERITY_ORDER.get(level.lower(), 0)


class AlertEmailSender:
    """Sends high-severity enriched alert dicts via SMTP.

    Only alerts whose ``level`` field is at or above *min_level* (default
    ``"high"``) are emailed.  A ``threading.Lock`` guards all socket I/O to
    ensure thread safety when the sender runs in the thread-pool executor.
    Call :meth:`close` during application shutdown to release any persistent
    SMTP connection resources.

    *use_tls* enables implicit TLS (``smtplib.SMTP_SSL``, typically port 465).
    *use_starttls* enables STARTTLS upgrade on a plain connection (typically
    port 587); it is ignored when *use_tls* is True.  When neither is set the
    connection is plain-text.
    """

    def __init__(
        self,
        smtp_host: str = "localhost",
        smtp_port: int = 587,
        username: str = "",
        password: str = "",
        use_tls: bool = False,
        use_starttls: bool = True,
        from_addr: str = "mxtac-alerts@localhost",
        to_addrs: Sequence[str] = (),
        min_level: str = _DEFAULT_MIN_LEVEL,
    ) -> None:
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._username = username
        self._password = password
        self._use_tls = use_tls
        self._use_starttls = use_starttls
        self._from_addr = from_addr
        self._to_addrs = list(to_addrs)
        self._min_rank = _severity_rank(min_level)
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers (run in thread-pool executor)
    # ------------------------------------------------------------------

    def _build_message(self, alert: dict[str, Any]) -> email.mime.multipart.MIMEMultipart:
        """Construct a MIME email from an enriched alert dict."""
        level = alert.get("level", "unknown").upper()
        host = alert.get("host", "unknown")
        title = alert.get("rule_title", alert.get("rule_id", "Unknown Rule"))
        score = alert.get("score", 0)

        subject = f"[MxTac Alert] [{level}] {title} — {host} (score {score})"

        msg = email.mime.multipart.MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self._from_addr
        msg["To"] = ", ".join(self._to_addrs)

        # Plain-text body: formatted JSON dump
        body_text = json.dumps(alert, indent=2, default=str)
        msg.attach(email.mime.text.MIMEText(body_text, "plain", "utf-8"))

        return msg

    def _send_sync(self, alert: dict[str, Any]) -> None:
        """Build and send one email synchronously (called from thread-pool)."""
        msg = self._build_message(alert)
        raw = msg.as_string()

        with self._lock:
            if self._use_tls:
                smtp: smtplib.SMTP = smtplib.SMTP_SSL(self._smtp_host, self._smtp_port)
            else:
                smtp = smtplib.SMTP(self._smtp_host, self._smtp_port)

            with smtp:
                if self._use_starttls and not self._use_tls:
                    smtp.starttls()
                if self._username:
                    smtp.login(self._username, self._password)
                smtp.sendmail(self._from_addr, self._to_addrs, raw)

    # ------------------------------------------------------------------
    # Public async interface
    # ------------------------------------------------------------------

    async def send(self, alert: dict[str, Any]) -> None:
        """Send *alert* via SMTP if it meets the minimum severity threshold.

        Alerts below *min_level* are silently dropped.  SMTP errors are
        logged and swallowed so that a delivery failure never interrupts the
        rest of the alert pipeline.
        """
        if not self._to_addrs:
            return

        level = alert.get("level", "")
        if _severity_rank(level) < self._min_rank:
            logger.debug(
                "AlertEmailSender skipping alert level=%s (below min=%s)",
                level,
                self._min_rank,
            )
            return

        try:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, self._send_sync, alert)
            logger.info(
                "AlertEmailSender sent email level=%s rule_id=%s host=%s",
                level,
                alert.get("rule_id", ""),
                alert.get("host", ""),
            )
        except Exception:
            logger.exception("AlertEmailSender send error (non-fatal)")

    async def close(self) -> None:
        """No-op — SMTP connections are opened per-message. Present for interface symmetry."""


async def alert_email_output(
    queue: MessageQueue,
    smtp_host: str = "localhost",
    smtp_port: int = 587,
    username: str = "",
    password: str = "",
    use_tls: bool = False,
    use_starttls: bool = True,
    from_addr: str = "mxtac-alerts@localhost",
    to_addrs: Sequence[str] = (),
    min_level: str = _DEFAULT_MIN_LEVEL,
) -> AlertEmailSender:
    """Subscribe an :class:`AlertEmailSender` to ``mxtac.enriched``.

    Returns the sender so the caller can close it during shutdown.
    """
    sender = AlertEmailSender(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        username=username,
        password=password,
        use_tls=use_tls,
        use_starttls=use_starttls,
        from_addr=from_addr,
        to_addrs=to_addrs,
        min_level=min_level,
    )

    async def _handle(alert: dict[str, Any]) -> None:
        await sender.send(alert)

    await queue.subscribe(Topic.ENRICHED, "alert-email-output", _handle)
    logger.info(
        "Alert email output subscribed to %s → smtp://%s:%d to=%s min_level=%s",
        Topic.ENRICHED,
        smtp_host,
        smtp_port,
        list(to_addrs),
        min_level,
    )
    return sender
