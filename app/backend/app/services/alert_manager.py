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
from typing import Any

import valkey.asyncio as aioredis
from prometheus_client import Counter, Histogram

from ..core.config import settings
from ..core.logging import get_logger
from ..engine.sigma_engine import SigmaAlert, LEVEL_SEVERITY
from ..pipeline.queue import MessageQueue, Topic

logger = get_logger(__name__)

# -- Prometheus custom metrics ------------------------------------------------
alerts_processed = Counter(
    "mxtac_alerts_processed_total",
    "Total alerts processed by the alert manager pipeline",
    ["severity"],
)
alerts_deduplicated = Counter(
    "mxtac_alerts_deduplicated_total",
    "Total alerts dropped by deduplication",
)
pipeline_latency = Histogram(
    "mxtac_pipeline_latency_seconds",
    "End-to-end alert pipeline processing latency in seconds",
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

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
    def __init__(self, queue: MessageQueue) -> None:
        self._queue = queue
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

    # -- Cleanup -----------------------------------------------------------

    async def close(self) -> None:
        """Close the Valkey connection."""
        if self._valkey:
            await self._valkey.aclose()
