"""
Alert Manager -- deduplication, enrichment, and scoring.

Consumes from mxtac.alerts and publishes to mxtac.enriched.

Deduplication window: same (rule_id, host) within 5 minutes = deduplicated.
Dedup is now backed by Valkey (Redis-compatible) using atomic SET NX EX so
that multiple backend replicas share a single dedup state.

Scoring formula:
    score = base_severity * weight_severity
          + asset_criticality * weight_asset
          + recurrence_bonus
    Normalized to 0-10 range.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import valkey.asyncio as aioredis

from ..core.config import settings
from ..core.logging import get_logger
from ..core.metrics import alerts_deduplicated, alerts_processed, pipeline_latency
from ..engine.sigma_engine import SigmaAlert, LEVEL_SEVERITY
from ..pipeline.queue import MessageQueue, Topic

if TYPE_CHECKING:
    from .notification_dispatcher import NotificationDispatcher

logger = get_logger(__name__)

# Score weights
W_SEVERITY  = 0.60
W_ASSET     = 0.25
W_RECUR     = 0.15
MAX_SCORE   = 10.0

# Deduplication window in seconds (5 minutes)
DEDUP_WINDOW_SECONDS = 300

# Valkey key prefix for dedup entries
_DEDUP_PREFIX = "mxtac:dedup:"

# Asset criticality defaults
DEFAULT_ASSET_CRITICALITY: dict[str, float] = {
    "dc":  1.0,   # Domain Controller prefix
    "srv": 0.8,
    "win": 0.6,
    "lin": 0.5,
}


class AlertManager:
    def __init__(
        self,
        queue: MessageQueue,
        dispatcher: NotificationDispatcher | None = None,
    ) -> None:
        self._queue = queue
        self._dispatcher = dispatcher
        # Valkey client for distributed deduplication
        self._valkey: aioredis.Valkey = aioredis.from_url(
            settings.valkey_url, decode_responses=True
        )

    async def process(self, alert_dict: dict[str, Any]) -> None:
        """Entry point -- called by queue consumer for each mxtac.alerts message."""
        start_time = time.monotonic()
        try:
            alert = SigmaAlert(
                id=alert_dict.get("id", ""),
                rule_id=alert_dict.get("rule_id", ""),
                rule_title=alert_dict.get("rule_title", ""),
                level=alert_dict.get("level", "medium"),
                severity_id=alert_dict.get("severity_id", 3),
                technique_ids=alert_dict.get("technique_ids", []),
                tactic_ids=alert_dict.get("tactic_ids", []),
                host=alert_dict.get("host", ""),
                time=datetime.fromisoformat(
                    alert_dict.get("time", datetime.now(timezone.utc).isoformat())
                ),
                event_snapshot=alert_dict.get("event_snapshot", {}),
            )

            severity_label = alert.level or "medium"
            alerts_processed.labels(severity=severity_label).inc()

            if await self._is_duplicate(alert):
                alerts_deduplicated.inc()
                logger.debug("AlertManager deduplicated rule_id=%s host=%s", alert.rule_id, alert.host)
                return

            enriched = await self._enrich(alert)
            scored   = self._score(enriched)

            await self._queue.publish(Topic.ENRICHED, scored)
            logger.info(
                "AlertManager published rule_id=%s host=%s score=%.1f",
                alert.rule_id, alert.host, scored.get("score", 0),
            )

            # Dispatch notifications — after enrichment, before storage (non-fatal)
            if self._dispatcher is not None:
                try:
                    await self._dispatcher.dispatch(scored)
                except Exception:
                    logger.exception(
                        "AlertManager notification dispatch failed (non-fatal) id=%s",
                        scored.get("id"),
                    )

            await self._persist_to_db(scored)
        except Exception:
            logger.exception("AlertManager process error")
        finally:
            pipeline_latency.observe(time.monotonic() - start_time)

    # -- Deduplication (Valkey-backed, distributed) -------------------------

    async def _is_duplicate(self, alert: SigmaAlert) -> bool:
        """Check if this alert is a duplicate using Valkey atomic SET NX EX.

        ``SET key "1" NX EX 300`` atomically:
          - Returns True  (set succeeded) when the key did NOT exist  -> *new* alert
          - Returns None  (set failed)    when the key already exists -> *duplicate*

        The 300-second TTL automatically evicts stale entries, replacing
        the old in-memory expiry sweep.
        """
        key = self._dedup_key(alert)
        try:
            was_set = await self._valkey.set(key, "1", nx=True, ex=DEDUP_WINDOW_SECONDS)
            # was_set is True when the key was newly created (not a duplicate)
            # was_set is None when the key already existed (duplicate)
            return was_set is None
        except Exception:
            logger.exception("Valkey dedup check failed, allowing alert through")
            # Fail-open: if Valkey is unreachable, let the alert through
            return False

    def _dedup_key(self, alert: SigmaAlert) -> str:
        raw = f"{alert.rule_id}|{alert.host}".encode()
        digest = hashlib.md5(raw).hexdigest()  # noqa: S324 (non-crypto use)
        return f"{_DEDUP_PREFIX}{digest}"

    # -- Enrichment --------------------------------------------------------

    async def _enrich(self, alert: SigmaAlert) -> dict[str, Any]:
        """Add context that isn't in the raw alert. Extend with real CTI lookups."""
        d = {
            "id":            alert.id,
            "rule_id":       alert.rule_id,
            "rule_title":    alert.rule_title,
            "level":         alert.level,
            "severity_id":   alert.severity_id,
            "technique_ids": alert.technique_ids,
            "tactic_ids":    alert.tactic_ids,
            "host":          alert.host,
            "time":          alert.time.isoformat(),
            "event_snapshot": alert.event_snapshot,
            # Enrichment placeholders (extend with real lookups)
            "asset_criticality": self._asset_criticality(alert.host),
            "threat_intel":      None,   # TODO: OpenCTI lookup
            "geo_ip":            None,   # TODO: GeoIP lookup
        }
        return d

    def _asset_criticality(self, hostname: str) -> float:
        """Simple prefix-based criticality -- replace with CMDB lookup."""
        if not hostname:
            return 0.5
        hn = hostname.lower()
        for prefix, crit in DEFAULT_ASSET_CRITICALITY.items():
            if hn.startswith(prefix):
                return crit
        return 0.5

    # -- Scoring -----------------------------------------------------------

    def _score(self, enriched: dict[str, Any]) -> dict[str, Any]:
        """Compute a 0-10 risk score and attach to the enriched alert."""
        severity_norm = (enriched["severity_id"] - 1) / 4   # 0-1
        asset_crit    = enriched.get("asset_criticality", 0.5)
        recur_bonus   = 0.0   # TODO: increment if seen multiple times

        raw_score = (
            severity_norm * W_SEVERITY
            + asset_crit  * W_ASSET
            + recur_bonus * W_RECUR
        ) * MAX_SCORE

        enriched["score"] = round(min(raw_score, MAX_SCORE), 1)
        return enriched

    # -- Persistence -------------------------------------------------------

    async def _persist_to_db(self, scored: dict[str, Any]) -> None:
        """Persist enriched alert to PostgreSQL. Non-fatal — pipeline continues on error."""
        try:
            from ..core.database import AsyncSessionLocal
            from ..repositories.detection_repo import DetectionRepo
            technique_ids = scored.get("technique_ids") or []
            tactic_ids    = scored.get("tactic_ids") or []
            alert_time    = datetime.fromisoformat(scored["time"])
            async with AsyncSessionLocal() as session:
                await DetectionRepo.create(
                    session,
                    id            = scored["id"],
                    score         = scored["score"],
                    severity      = scored["level"],
                    technique_id  = (technique_ids[0] if technique_ids else "unknown")[:20],
                    technique_name= scored["rule_title"][:255],
                    tactic        = (tactic_ids[0] if tactic_ids else "unknown")[:100],
                    tactic_id     = tactic_ids[0] if tactic_ids else None,
                    name          = scored["rule_title"][:500],
                    host          = scored["host"],
                    time          = alert_time,
                    rule_name     = (scored["rule_id"] or "")[:500] or None,
                )
                await self._correlate_incident(session, scored)
                await session.commit()
            logger.debug("AlertManager persisted detection id=%s", scored["id"])
        except Exception:
            logger.exception(
                "AlertManager DB persistence failed (non-fatal) id=%s", scored.get("id")
            )

    # -- Auto-correlation --------------------------------------------------

    # Severity rank: higher index = higher severity
    _SEVERITY_RANK: dict[str, int] = {
        "low": 0, "medium": 1, "high": 2, "critical": 3,
    }

    async def _correlate_incident(self, session: Any, scored: dict[str, Any]) -> None:
        """Auto-correlate this detection into an incident (feature 26.8).

        Logic:
        1. If auto_create_incident_enabled is False, do nothing.
        2. Look for an open incident with (host, tactic) within correlation_window_seconds.
           If found: append this detection_id to its detection_ids list.
        3. If not found and severity >= auto_create_incident_min_severity: create a new incident.
        """
        if not settings.auto_create_incident_enabled:
            return

        host       = scored.get("host", "")
        tactic_ids = scored.get("tactic_ids") or []
        tactic     = tactic_ids[0] if tactic_ids else ""
        detection_id = scored.get("id", "")
        severity   = scored.get("level", "medium")

        if not host or not tactic or not detection_id:
            return

        from ..repositories.incident_repo import IncidentRepo

        existing = await IncidentRepo.find_open_by_host_tactic(
            session,
            host=host,
            tactic=tactic,
            window_seconds=settings.correlation_window_seconds,
        )

        if existing:
            # Append detection_id if not already present
            ids = list(existing.detection_ids or [])
            if detection_id not in ids:
                ids.append(detection_id)
                existing.detection_ids = ids
            logger.info(
                "AlertManager correlated detection=%s into incident=%s (host=%s tactic=%s)",
                detection_id, existing.id, host, tactic,
            )
            return

        # Check severity threshold for new incident creation
        min_rank = self._SEVERITY_RANK.get(settings.auto_create_incident_min_severity, 2)
        alert_rank = self._SEVERITY_RANK.get(severity, 0)
        if alert_rank < min_rank:
            return

        from ..repositories.incident_repo import IncidentRepo
        technique_ids = scored.get("technique_ids") or []
        await IncidentRepo.create(
            session,
            title        = f"Auto: {scored.get('rule_title', 'Unknown')} on {host}",
            description  = (
                f"Auto-created by alert-to-incident correlation.\n"
                f"Rule: {scored.get('rule_id', '')}\n"
                f"Host: {host}\n"
                f"Tactic: {tactic}"
            ),
            severity     = severity,
            status       = "new",
            priority     = 3,
            created_by   = "system",
            detection_ids= [detection_id],
            technique_ids= technique_ids,
            tactic_ids   = tactic_ids,
            hosts        = [host],
        )
        logger.info(
            "AlertManager created new incident for detection=%s (host=%s tactic=%s severity=%s)",
            detection_id, host, tactic, severity,
        )

    # -- Cleanup -----------------------------------------------------------

    async def close(self) -> None:
        """Close the Valkey connection."""
        if self._valkey:
            await self._valkey.aclose()
