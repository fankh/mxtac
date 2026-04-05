"""
Scheduled Detection Engine — per-target aggregation with dedup.

Ported from KYRA MDR's DetectionEngineService.java.
Runs every 60 seconds, evaluates active detection rules against OpenSearch,
creates per-target alerts with 24-hour deduplication window.

Key features:
  - Per-target IP aggregation (NDR: dst_ip, Syslog: hostname)
  - Adaptive skip (inactive rules checked less frequently)
  - 24-hour dedup window per rule+target (merges occurrence count)
  - Broad query rejection (prevents false positives from overly simple queries)
  - Auto-escalation for critical/high severity rules
  - Max 10 targets per rule per cycle (prevents alert explosion)
"""

from __future__ import annotations

import asyncio
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from ..core.config import settings
from ..core.logging import get_logger

logger = get_logger(__name__)

# --- Constants ---
CYCLE_INTERVAL_SECONDS = 300  # 5 minutes (KYRA uses 60s but MxTac is lighter)
FULL_RECHECK_INTERVAL = 30  # every 30 cycles, force all rules checked
ALERT_DEDUP_HOURS = 24
MAX_TARGETS_PER_RULE = 10
BROAD_QUERY_PATTERN = re.compile(r"^source=\w+$")


class DetectionEngine:
    """Scheduled detection engine with per-target aggregation and dedup."""

    def __init__(
        self,
        os_client: Any,
        detection_repo: Any,
        rule_repo: Any,
        alert_manager: Any | None = None,
    ):
        self.os_client = os_client
        self.detection_repo = detection_repo
        self.rule_repo = rule_repo
        self.alert_manager = alert_manager

        # State maps (in-memory, reset on restart)
        self._last_run: dict[str, datetime] = {}
        self._consecutive_zeros: dict[str, int] = defaultdict(int)
        self._cycle_counter = 0
        self._running = False
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the detection engine background loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Detection engine started (interval=%ds)", CYCLE_INTERVAL_SECONDS)

    async def stop(self) -> None:
        """Stop the detection engine."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Detection engine stopped")

    async def _run_loop(self) -> None:
        """Main loop — runs detection cycles at fixed intervals."""
        # Initial delay to let other services start
        await asyncio.sleep(10)
        while self._running:
            try:
                await self.run_cycle()
            except Exception:
                logger.exception("Detection cycle failed")
            await asyncio.sleep(CYCLE_INTERVAL_SECONDS)

    async def run_cycle(self) -> None:
        """Execute one detection cycle across all active rules."""
        self._cycle_counter += 1
        full_recheck = self._cycle_counter % FULL_RECHECK_INTERVAL == 0

        rules = await self.rule_repo.list_active()
        if not rules:
            return

        checked = skipped = triggered = 0
        now = datetime.now(timezone.utc)

        for rule in rules:
            try:
                rule_id = str(rule.id)
                query = (rule.content or "").strip() if hasattr(rule, "content") else ""
                # Use query field if content is YAML (check for simple query syntax)
                if hasattr(rule, "query") and rule.query:
                    query = rule.query.strip()

                # Skip overly broad queries
                if BROAD_QUERY_PATTERN.match(query):
                    logger.debug(
                        "Skipping broad rule '%s': query='%s'", rule.title, query
                    )
                    skipped += 1
                    continue

                # Adaptive skip (unless full recheck)
                if not full_recheck:
                    zeros = self._consecutive_zeros[rule_id]
                    if zeros >= 10 and self._cycle_counter % 15 != 0:
                        skipped += 1
                        continue
                    if zeros >= 3 and self._cycle_counter % 5 != 0:
                        skipped += 1
                        continue

                since = self._last_run.get(rule_id, now - timedelta(seconds=CYCLE_INTERVAL_SECONDS))
                targets = await self._aggregate_by_target(rule, since, now)
                checked += 1

                if targets:
                    self._consecutive_zeros[rule_id] = 0
                    targets_processed = 0
                    for target_ip, count in targets.items():
                        if targets_processed >= MAX_TARGETS_PER_RULE:
                            break
                        await self._on_rule_triggered(rule, target_ip, count, since, now)
                        targets_processed += 1
                    triggered += 1
                else:
                    self._consecutive_zeros[rule_id] += 1

                self._last_run[rule_id] = now

            except Exception:
                logger.debug("Detection failed for rule '%s'", getattr(rule, "title", "?"), exc_info=True)

        suffix = " [FULL RECHECK]" if full_recheck else ""
        logger.info(
            "Detection cycle #%d: checked=%d, skipped=%d, triggered=%d, total=%d%s",
            self._cycle_counter, checked, skipped, triggered, len(rules), suffix,
        )

    # --- OpenSearch aggregation ---

    async def _aggregate_by_target(
        self, rule: Any, since: datetime, until: datetime
    ) -> dict[str, int]:
        """Aggregate events by target IP using OpenSearch terms aggregation."""
        query_text = getattr(rule, "query", "") or getattr(rule, "content", "") or ""
        is_ndr = "source=ndr" in query_text or "network" in (getattr(rule, "logsource_category", "") or "")

        # Build index pattern
        today = datetime.now(timezone.utc).strftime("%Y.%m.%d")
        if is_ndr:
            index = f"mxtac-events-{today}"
            agg_field = "dst_endpoint.ip"
        else:
            # Syslog: search last 3 days
            dates = [(datetime.now(timezone.utc) - timedelta(days=d)).strftime("%Y.%m.%d") for d in range(3)]
            index = ",".join(f"mxtac-events-{d}" for d in dates)
            agg_field = "src_endpoint.hostname.keyword"

        # Build query
        bool_query = self._build_query(query_text, since, until)

        body: dict[str, Any] = {
            "size": 0,
            "query": bool_query,
            "aggs": {
                "by_target": {
                    "terms": {"field": agg_field, "size": 50}
                }
            },
        }

        try:
            client = self.os_client._client if hasattr(self.os_client, "_client") else None
            if client is None:
                return {}
            resp = await client.search(index=index, body=body, ignore_unavailable=True)
            buckets = resp.get("aggregations", {}).get("by_target", {}).get("buckets", [])
            result: dict[str, int] = {}
            for bucket in buckets:
                key = bucket.get("key", "")
                count = bucket.get("doc_count", 0)
                if key and count > 0:
                    result[key] = count

            # Fallback: if no target-level buckets, use total hits
            if not result:
                total = resp.get("hits", {}).get("total", {})
                total_val = total.get("value", 0) if isinstance(total, dict) else int(total or 0)
                if total_val > 0:
                    result["internal"] = total_val

            return result
        except Exception:
            logger.debug("Aggregation failed for rule '%s'", getattr(rule, "title", "?"), exc_info=True)
            return {}

    def _build_query(self, query_text: str, since: datetime, until: datetime) -> dict:
        """Parse simple query syntax into OpenSearch bool query."""
        must: list[dict] = [
            {"range": {"time": {"gte": since.isoformat(), "lte": until.isoformat()}}},
        ]
        must_not: list[dict] = []

        # Strip pipe section
        filter_part = query_text.split("|")[0].strip()

        # Parse field=value, field>N, field<N patterns
        for token in re.findall(r'(\w+)\s*(>=|<=|>|<|=)\s*("[^"]*"|\S+)', filter_part):
            field, op, value = token
            value = value.strip('"')

            if field in ("source",):
                # Map "source" to the actual field
                must.append({"term": {"source": value}})
            elif op == "=":
                if "*" in value:
                    must.append({"wildcard": {field: value}})
                else:
                    must.append({"term": {field: value}})
            elif op == ">":
                must.append({"range": {field: {"gt": self._parse_number(value)}}})
            elif op == ">=":
                must.append({"range": {field: {"gte": self._parse_number(value)}}})
            elif op == "<":
                must.append({"range": {field: {"lt": self._parse_number(value)}}})
            elif op == "<=":
                must.append({"range": {field: {"lte": self._parse_number(value)}}})

        # Safety: if no real filters, return match_none
        if len(must) <= 1 and not must_not:
            return {"match_none": {}}

        query: dict[str, Any] = {"bool": {"must": must}}
        if must_not:
            query["bool"]["must_not"] = must_not
        return query

    @staticmethod
    def _parse_number(val: str) -> int | float:
        try:
            return int(val)
        except ValueError:
            try:
                return float(val)
            except ValueError:
                return 0

    # --- Alert creation with per-target dedup ---

    async def _on_rule_triggered(
        self, rule: Any, target: str, count: int, since: datetime, until: datetime
    ) -> None:
        """Create or merge alert for a specific rule + target combination."""
        rule_id = str(rule.id)
        rule_name = getattr(rule, "title", rule_id)
        severity = getattr(rule, "level", "medium") or "medium"
        is_ndr = "source=ndr" in (getattr(rule, "query", "") or getattr(rule, "content", "") or "")

        # Check for existing alert within dedup window
        dedup_since = datetime.now(timezone.utc) - timedelta(hours=ALERT_DEDUP_HOURS)
        existing = await self.detection_repo.find_recent_by_rule_and_target(
            rule_id, target, dedup_since
        )

        if existing:
            # Merge into existing detection
            await self.detection_repo.increment_occurrence(
                existing.id, count, datetime.now(timezone.utc)
            )
            logger.info(
                "Detection dedup: rule='%s' target=%s count=%d merged into id=%s",
                rule_name, target, count, existing.id,
            )
            return

        # Create new detection
        technique_ids = getattr(rule, "technique_ids", []) or []
        tactic_ids = getattr(rule, "tactic_ids", []) or []
        technique = technique_ids[0] if technique_ids else None
        tactic = tactic_ids[0] if tactic_ids else None

        detection_data = {
            "id": str(uuid4()),
            "name": f"[Detection] {rule_name} → {target}",
            "description": f"Rule '{rule_name}' matched {count} events targeting {target}",
            "severity": severity.lower(),
            "status": "open",
            "score": self._calculate_score(severity, count),
            "technique_id": technique,
            "tactic": tactic,
            "host": target if target != "internal" else None,
            "rule_name": rule_name,
            "log_source": "ndr" if is_ndr else "syslog",
            "occurrence_count": count,
            "time": datetime.now(timezone.utc),
            "confidence": 0.85 if is_ndr else 0.75,
            "extra": {
                "target_ip": target if target != "internal" else None,
                "data_source": "network-logs (NDR)" if is_ndr else "events (Syslog)",
                "rule_query": getattr(rule, "query", "") or getattr(rule, "content", ""),
                "match_count": count,
                "mitre_technique": technique,
                "mitre_tactic": tactic,
            },
        }

        try:
            await self.detection_repo.create_from_engine(detection_data)
            logger.info(
                "Detection: rule='%s' target=%s count=%d id=%s",
                rule_name, target, count, detection_data["id"],
            )

            # Auto-escalate critical/high to incidents
            if severity.lower() in ("critical", "high"):
                await self._auto_escalate(rule_name, severity, target, detection_data["id"])

        except Exception:
            logger.warning("Failed to persist detection for rule '%s'", rule_name, exc_info=True)

        # Update rule stats
        try:
            await self.rule_repo.increment_hit_count(rule.id, count)
        except Exception:
            pass

    @staticmethod
    def _calculate_score(severity: str, count: int) -> float:
        """Calculate detection score (0-10) based on severity and hit count."""
        base = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0}.get(
            severity.lower(), 5.0
        )
        # Volume bonus: log scale, max +1.0
        import math
        volume_bonus = min(1.0, math.log10(max(count, 1)) / 4)
        return min(10.0, base + volume_bonus)

    async def _auto_escalate(
        self, rule_name: str, severity: str, target: str, detection_id: str
    ) -> None:
        """Auto-create incident for critical/high detections (1 per rule per 24h)."""
        try:
            incident_title = f"[Auto] {rule_name}"
            # Check if incident already exists in last 24h
            existing = await self.detection_repo.find_recent_incident(
                incident_title, timedelta(hours=24)
            )
            if existing:
                return

            await self.detection_repo.create_incident(
                title=f"{incident_title} → {target}",
                severity=severity,
                detection_id=detection_id,
                description=f"Auto-created from detection rule '{rule_name}' targeting {target}",
            )
            logger.info("Auto-incident for detection: rule='%s' target=%s", rule_name, target)
        except Exception:
            logger.debug("Auto-escalation skipped: %s", rule_name, exc_info=True)
