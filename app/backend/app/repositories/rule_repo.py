"""Rule repository — async DB operations for the rules table."""

from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.rule import Rule

# ATT&CK v14 scope — total sub-techniques across the 9 tracked tactics (same as detection_repo)
_RULE_COVERAGE_TOTAL = 105

# ---------------------------------------------------------------------------
# Logsource → connector type mapping (Sigma convention)
# ---------------------------------------------------------------------------

_WAZUH_PRODUCTS = frozenset({"windows", "linux", "macos", "unix", "endpoint"})
_ZEEK_PRODUCTS = frozenset({"zeek"})
_ZEEK_CATEGORIES = frozenset({"network_connection", "network_flow", "dns", "proxy", "http", "ssl", "network"})
_SURICATA_PRODUCTS = frozenset({"suricata"})

_KNOWN_SOURCES = ("wazuh", "zeek", "suricata")


def _classify_logsource(product: str | None, category: str | None, service: str | None) -> str | None:
    """Map Sigma logsource fields to a connector type name.

    Returns "wazuh", "zeek", "suricata", or None when no match is found.
    """
    p = (product or "").lower().strip()
    c = (category or "").lower().strip()
    s = (service or "").lower().strip()

    if p in _WAZUH_PRODUCTS:
        return "wazuh"
    if p in _ZEEK_PRODUCTS or c in _ZEEK_CATEGORIES:
        return "zeek"
    if p in _SURICATA_PRODUCTS or "suricata" in s:
        return "suricata"
    return None


class RuleRepo:

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        enabled: bool | None = None,
        level: str | None = None,
    ) -> list[Rule]:
        q = select(Rule)
        if enabled is not None:
            q = q.where(Rule.enabled == enabled)
        if level:
            q = q.where(Rule.level == level)
        q = q.order_by(Rule.created_at.desc())
        result = await session.execute(q)
        return list(result.scalars().all())

    @staticmethod
    async def get_by_id(session: AsyncSession, rule_id: str) -> Rule | None:
        result = await session.execute(select(Rule).where(Rule.id == rule_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> Rule:
        rule = Rule(**kwargs)
        session.add(rule)
        await session.flush()
        return rule

    @staticmethod
    async def update(session: AsyncSession, rule_id: str, **kwargs) -> Rule | None:
        rule = await RuleRepo.get_by_id(session, rule_id)
        if not rule:
            return None
        for k, v in kwargs.items():
            if v is not None:
                setattr(rule, k, v)
        await session.flush()
        return rule

    @staticmethod
    async def enable(session: AsyncSession, rule_id: str) -> Rule | None:
        return await RuleRepo.update(session, rule_id, enabled=True)

    @staticmethod
    async def disable(session: AsyncSession, rule_id: str) -> Rule | None:
        return await RuleRepo.update(session, rule_id, enabled=False)

    @staticmethod
    async def delete(session: AsyncSession, rule_id: str) -> bool:
        rule = await RuleRepo.get_by_id(session, rule_id)
        if not rule:
            return False
        await session.delete(rule)
        await session.flush()
        return True

    @staticmethod
    async def count(session: AsyncSession) -> int:
        result = await session.scalar(select(func.count()).select_from(Rule))
        return result or 0

    @staticmethod
    async def get_kpi_counts(session: AsyncSession, *, week_start: datetime) -> dict:
        """Return rule statistics for the KPI endpoint.

        Keys:
            active               — enabled rules
            critical             — enabled rules with level='critical'
            high                 — enabled rules with level='high'
            deployed_this_week   — rules created since week_start
        """
        active = await session.scalar(
            select(func.count()).select_from(Rule).where(Rule.enabled == True)  # noqa: E712
        ) or 0

        critical = await session.scalar(
            select(func.count())
            .select_from(Rule)
            .where(Rule.enabled == True)  # noqa: E712
            .where(Rule.level == "critical")
        ) or 0

        high = await session.scalar(
            select(func.count())
            .select_from(Rule)
            .where(Rule.enabled == True)  # noqa: E712
            .where(Rule.level == "high")
        ) or 0

        deployed_this_week = await session.scalar(
            select(func.count()).select_from(Rule).where(Rule.created_at >= week_start)
        ) or 0

        return {
            "active": active,
            "critical": critical,
            "high": high,
            "deployed_this_week": deployed_this_week,
        }

    @staticmethod
    async def get_coverage_summary(session: AsyncSession) -> dict | None:
        """Return ATT&CK coverage based on active enabled rules.

        Parses ``technique_ids`` JSON arrays from all enabled rules and returns
        the count of distinct techniques covered vs. the total in scope (105).
        Returns None when no enabled rules with technique mappings exist
        (caller falls back to mock data).
        """
        result = await session.execute(
            select(Rule.technique_ids)
            .where(Rule.enabled == True)  # noqa: E712
            .where(Rule.technique_ids.is_not(None))
        )
        rows = result.scalars().all()

        if not rows:
            return None

        covered: set[str] = set()
        for technique_ids_json in rows:
            try:
                ids = json.loads(technique_ids_json)
                for tid in ids:
                    if isinstance(tid, str) and tid.strip():
                        covered.add(tid.strip())
            except (ValueError, TypeError):
                continue

        if not covered:
            return None

        covered_count = min(len(covered), _RULE_COVERAGE_TOTAL)
        coverage_pct = round(covered_count / _RULE_COVERAGE_TOTAL * 100, 1)

        return {
            "coverage_pct": coverage_pct,
            "covered_count": covered_count,
            "total_count": _RULE_COVERAGE_TOTAL,
        }

    @staticmethod
    async def get_navigator_techniques(session: AsyncSession) -> dict[str, int]:
        """Return enabled-rule coverage counts per technique for Navigator export.

        Returns a mapping of technique_id → count of enabled rules covering it.
        Only enabled rules are included; disabled rules are excluded entirely.
        """
        result = await session.execute(
            select(Rule.technique_ids)
            .where(Rule.enabled == True)  # noqa: E712
            .where(Rule.technique_ids.is_not(None))
        )
        rows = result.scalars().all()

        technique_counts: dict[str, int] = {}
        for technique_ids_json in rows:
            try:
                ids = json.loads(technique_ids_json)
                for tid in ids:
                    if isinstance(tid, str) and tid.strip():
                        key = tid.strip()
                        technique_counts[key] = technique_counts.get(key, 0) + 1
            except (ValueError, TypeError):
                continue

        return technique_counts

    @staticmethod
    async def get_coverage_by_datasource(session: AsyncSession) -> dict:
        """Return ATT&CK coverage broken down by data source connector.

        Groups enabled rules by their Sigma logsource (product/category/service)
        and counts distinct technique IDs per connector type (wazuh, zeek, suricata).
        Rules whose logsource cannot be mapped to a known connector are skipped.

        The aggregate ``total_covered_count`` reflects all unique techniques
        covered across all sources combined (union, not sum).
        """
        result = await session.execute(
            select(
                Rule.technique_ids,
                Rule.logsource_product,
                Rule.logsource_category,
                Rule.logsource_service,
            )
            .where(Rule.enabled == True)  # noqa: E712
            .where(Rule.technique_ids.is_not(None))
        )
        rows = result.all()

        covered_by_source: dict[str, set[str]] = {s: set() for s in _KNOWN_SOURCES}
        rule_count_by_source: dict[str, int] = {s: 0 for s in _KNOWN_SOURCES}

        for technique_ids_json, product, category, service in rows:
            source = _classify_logsource(product, category, service)
            if source is None:
                continue
            rule_count_by_source[source] += 1
            try:
                ids = json.loads(technique_ids_json)
                for tid in ids:
                    if isinstance(tid, str) and tid.strip():
                        covered_by_source[source].add(tid.strip())
            except (ValueError, TypeError):
                continue

        all_covered: set[str] = set()
        for s in _KNOWN_SOURCES:
            all_covered |= covered_by_source[s]

        sources = [
            {
                "source": s,
                "covered_count": min(len(covered_by_source[s]), _RULE_COVERAGE_TOTAL),
                "total_count": _RULE_COVERAGE_TOTAL,
                "coverage_pct": round(
                    min(len(covered_by_source[s]), _RULE_COVERAGE_TOTAL) / _RULE_COVERAGE_TOTAL * 100,
                    1,
                ),
                "rule_count": rule_count_by_source[s],
            }
            for s in _KNOWN_SOURCES
        ]

        total_covered = min(len(all_covered), _RULE_COVERAGE_TOTAL)
        return {
            "sources": sources,
            "total_covered_count": total_covered,
            "total_count": _RULE_COVERAGE_TOTAL,
            "total_coverage_pct": round(total_covered / _RULE_COVERAGE_TOTAL * 100, 1),
        }

    @staticmethod
    async def get_enabled_rule_counts_by_technique(session: AsyncSession) -> dict[str, int]:
        """Return count of enabled rules per ATT&CK technique ID.

        Used by the hunt suggestions engine to annotate each suggestion with
        how many active Sigma rules already cover the technique, helping
        analysts gauge their existing detection posture.

        Returns an empty dict when no enabled rules with technique mappings exist.
        """
        result = await session.execute(
            select(Rule.technique_ids)
            .where(Rule.enabled == True)  # noqa: E712
            .where(Rule.technique_ids.is_not(None))
        )
        counts: dict[str, int] = {}
        for technique_ids_json in result.scalars().all():
            try:
                ids = json.loads(technique_ids_json)
                for tid in ids:
                    if isinstance(tid, str) and tid.strip():
                        key = tid.strip()
                        counts[key] = counts.get(key, 0) + 1
            except (ValueError, TypeError):
                continue
        return counts

    @staticmethod
    async def get_coverage_gaps(session: AsyncSession) -> dict:
        """Return ATT&CK coverage gap data based on enabled vs. all rules.

        Collects technique IDs from:
          - enabled rules  → covered set
          - all rules      → known set (enabled + disabled)

        ``uncovered_techniques`` = technique IDs that appear in ANY rule but
        are NOT covered by any enabled rule.  These are actionable: the operator
        already has detection logic but it is disabled.

        ``gap_count`` = total in scope (105) - covered_count.
        ``coverage_pct`` = covered_count / total * 100 (capped at 100).
        """
        # Collect technique IDs from all enabled rules
        enabled_result = await session.execute(
            select(Rule.technique_ids)
            .where(Rule.enabled == True)  # noqa: E712
            .where(Rule.technique_ids.is_not(None))
        )
        enabled_rows = enabled_result.scalars().all()

        covered: set[str] = set()
        for technique_ids_json in enabled_rows:
            try:
                ids = json.loads(technique_ids_json)
                for tid in ids:
                    if isinstance(tid, str) and tid.strip():
                        covered.add(tid.strip())
            except (ValueError, TypeError):
                continue

        # Collect technique IDs from all rules (including disabled)
        all_result = await session.execute(
            select(Rule.technique_ids).where(Rule.technique_ids.is_not(None))
        )
        all_rows = all_result.scalars().all()

        all_known: set[str] = set()
        for technique_ids_json in all_rows:
            try:
                ids = json.loads(technique_ids_json)
                for tid in ids:
                    if isinstance(tid, str) and tid.strip():
                        all_known.add(tid.strip())
            except (ValueError, TypeError):
                continue

        # Techniques in any rule but NOT in enabled rules — actionable gaps
        uncovered_techniques = sorted(all_known - covered)

        covered_count = min(len(covered), _RULE_COVERAGE_TOTAL)
        gap_count = _RULE_COVERAGE_TOTAL - covered_count
        coverage_pct = round(covered_count / _RULE_COVERAGE_TOTAL * 100, 1)

        return {
            "covered_count": covered_count,
            "total_count": _RULE_COVERAGE_TOTAL,
            "gap_count": gap_count,
            "coverage_pct": coverage_pct,
            "uncovered_techniques": uncovered_techniques,
        }
