"""Detection repository — async DB operations for the detections table."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from math import ceil

from sqlalchemy import case, func, select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.validators import escape_like
from ..engine.sigma_engine import TACTIC_ID_TO_NAME, tactic_name
from ..models.detection import Detection

# Severity rank for sorting: descending puts the most severe first.
_SEVERITY_RANK = case(
    {"critical": 4, "high": 3, "medium": 2, "low": 1},
    value=Detection.severity,
    else_=0,
)

# ---------------------------------------------------------------------------
# Heatmap constants
# ---------------------------------------------------------------------------

# ATT&CK tactic full name → heatmap column abbreviation
_TACTIC_LABEL_MAP: dict[str, str] = {
    "Reconnaissance": "RECON",
    "Resource Development": "RES",
    "Initial Access": "INIT",
    "Execution": "EXEC",
    "Persistence": "PERS",
    "Privilege Escalation": "PRIV",
    "Defense Evasion": "DEF-E",
    "Credential Access": "CRED",
    "Discovery": "DISC",
}

# Total ATT&CK sub-techniques per tactic column (v14 metadata — static)
_TACTIC_TOTALS: dict[str, int] = {
    "RECON": 9, "RES": 6, "INIT": 9, "EXEC": 14,
    "PERS": 12, "PRIV": 11, "DEF-E": 17, "CRED": 14, "DISC": 13,
}

# Ordered heatmap column labels (also served by GET /overview/coverage/tactic-labels)
TACTIC_LABELS = ["RECON", "RES", "INIT", "EXEC", "PERS", "PRIV", "DEF-E", "CRED", "DISC"]
_HEATMAP_TECHNIQUE_FAMILIES = ["T1059", "T1003", "T1021", "T1078"]


def _count_by_tactic_name(rows) -> dict[str, int]:
    """Sum ``(tactic, count)`` rows per tactic name.

    Rows written by older versions hold the tactic ID (``TA0006``); they are
    counted under the tactic name, together with the rows that hold the name.
    """
    counts: dict[str, int] = {}
    for row in rows:
        name = tactic_name(row.tactic)
        counts[name] = counts.get(name, 0) + int(row.count)
    return counts


class DetectionRepo:

    @staticmethod
    async def list(
        session: AsyncSession,
        *,
        page: int = 1,
        page_size: int = 25,
        severity: list[str] | None = None,
        status: list[str] | None = None,
        tactic: str | None = None,
        host: str | None = None,
        search: str | None = None,
        sort: str = "time",
        order: str = "desc",
    ) -> tuple[list[Detection], int]:
        """Return (items, total_count) with filtering, sorting, and pagination."""
        q = select(Detection)

        if severity:
            q = q.where(Detection.severity.in_(severity))
        if status:
            q = q.where(Detection.status.in_(status))
        if tactic:
            # Rows written by older versions hold the tactic ID instead of the
            # name; match them through the IDs whose name contains the filter.
            legacy_ids = [
                tid for tid, name in TACTIC_ID_TO_NAME.items()
                if tactic.strip().lower() in name.lower()
            ]
            q = q.where(
                Detection.tactic.ilike(f"%{escape_like(tactic)}%", escape="\\")
                | Detection.tactic.in_(legacy_ids)
            )
        if host:
            q = q.where(Detection.host.ilike(f"%{escape_like(host)}%", escape="\\"))
        if search:
            pattern = f"%{escape_like(search)}%"
            q = q.where(
                Detection.name.ilike(pattern, escape="\\")
                | Detection.description.ilike(pattern, escape="\\")
                | Detection.technique_id.ilike(pattern, escape="\\")
                | Detection.host.ilike(pattern, escape="\\")
            )

        # Count
        count_q = select(func.count()).select_from(q.subquery())
        total = await session.scalar(count_q) or 0

        # Sort
        # Severity is sorted by rank, not by its name ("high" < "low" < "medium").
        # Time and ID break ties, so rows keep one order across pages.
        sort_col = _SEVERITY_RANK if sort == "severity" else getattr(Detection, sort, Detection.time)
        q = q.order_by(
            sort_col.desc() if order == "desc" else sort_col.asc(),
            Detection.time.desc(),
            Detection.id,
        )

        # Paginate
        offset = (page - 1) * page_size
        q = q.offset(offset).limit(page_size)

        result = await session.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def get(session: AsyncSession, detection_id: str) -> Detection | None:
        result = await session.execute(
            select(Detection).where(Detection.id == detection_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(session: AsyncSession, **kwargs) -> Detection:
        det = Detection(**kwargs)
        session.add(det)
        await session.flush()
        return det

    @staticmethod
    async def update(session: AsyncSession, detection_id: str, **kwargs) -> Detection | None:
        det = await DetectionRepo.get(session, detection_id)
        if not det:
            return None
        for k, v in kwargs.items():
            if v is not None:
                setattr(det, k, v)
        await session.flush()
        return det

    @staticmethod
    async def delete(session: AsyncSession, detection_id: str) -> bool:
        det = await DetectionRepo.get(session, detection_id)
        if not det:
            return False
        await session.delete(det)
        await session.flush()
        return True

    @staticmethod
    async def count(session: AsyncSession) -> int:
        result = await session.scalar(select(func.count()).select_from(Detection))
        return result or 0

    @staticmethod
    async def bulk_update_status(
        session: AsyncSession, ids: list[str], status: str
    ) -> dict:
        """Update status for multiple detections by ID.

        Returns a dict with:
            updated   — number of detections successfully updated
            not_found — list of IDs that were not found in the database
        """
        found_result = await session.execute(
            select(Detection.id).where(Detection.id.in_(ids))
        )
        found_ids = [row[0] for row in found_result.all()]

        if found_ids:
            await session.execute(
                sa_update(Detection)
                .where(Detection.id.in_(found_ids))
                .values(status=status)
            )
            await session.flush()

        not_found = [id_ for id_ in ids if id_ not in set(found_ids)]
        return {"updated": len(found_ids), "not_found": not_found}

    @staticmethod
    async def get_tactics(
        session: AsyncSession,
        *,
        from_date: datetime,
        to_date: datetime,
        prev_from_date: datetime,
    ) -> list[dict]:
        """Return per-tactic detection counts + trend_pct for a date range.

        trend_pct compares the current period (from_date..to_date) to the
        immediately preceding period of equal length (prev_from_date..from_date).
        Returns an empty list when no detections exist in the current period.
        """
        current_q = (
            select(
                Detection.tactic.label("tactic"),
                func.count().label("count"),
            )
            .where(Detection.time >= from_date)
            .where(Detection.time <= to_date)
            .group_by(Detection.tactic)
            .order_by(func.count().desc())
        )
        current_result = await session.execute(current_q)
        current_rows = _count_by_tactic_name(current_result.all())

        if not current_rows:
            return []

        prev_q = (
            select(
                Detection.tactic.label("tactic"),
                func.count().label("count"),
            )
            .where(Detection.time >= prev_from_date)
            .where(Detection.time < from_date)
            .group_by(Detection.tactic)
        )
        prev_result = await session.execute(prev_q)
        prev_rows = _count_by_tactic_name(prev_result.all())

        result = []
        for tactic, count in sorted(current_rows.items(), key=lambda x: -x[1]):
            prev_count = prev_rows.get(tactic, 0)
            if prev_count > 0:
                trend_pct = round((count - prev_count) / prev_count * 100, 1)
            else:
                trend_pct = 0.0
            result.append({"tactic": tactic, "count": count, "trend_pct": trend_pct})

        return result

    @staticmethod
    async def get_kpi_counts(
        session: AsyncSession,
        *,
        from_date: datetime,
        to_date: datetime,
        prev_from_date: datetime,
        today_start: datetime,
    ) -> dict:
        """Return detection counts needed for the KPI endpoint.

        Keys:
            total_current  — detections in [from_date, to_date]
            total_prev     — detections in [prev_from_date, from_date)
            critical       — critical-severity detections in [from_date, to_date]
            critical_today — critical-severity detections since today_start
        """
        total_current = await session.scalar(
            select(func.count())
            .select_from(Detection)
            .where(Detection.time >= from_date)
            .where(Detection.time <= to_date)
        ) or 0

        total_prev = await session.scalar(
            select(func.count())
            .select_from(Detection)
            .where(Detection.time >= prev_from_date)
            .where(Detection.time < from_date)
        ) or 0

        critical = await session.scalar(
            select(func.count())
            .select_from(Detection)
            .where(Detection.time >= from_date)
            .where(Detection.time <= to_date)
            .where(Detection.severity == "critical")
        ) or 0

        critical_today = await session.scalar(
            select(func.count())
            .select_from(Detection)
            .where(Detection.time >= today_start)
            .where(Detection.severity == "critical")
        ) or 0

        return {
            "total_current": total_current,
            "total_prev": total_prev,
            "critical": critical,
            "critical_today": critical_today,
        }

    @staticmethod
    async def get_coverage_summary(session: AsyncSession) -> dict | None:
        """Return overall ATT&CK coverage: distinct technique_ids detected vs. total in scope.

        total_count is the sum of all sub-technique slots tracked across the 9 heatmap tactics
        (ATT&CK v14 scope = 105). Returns None when no detections exist.
        """
        total_count = sum(_TACTIC_TOTALS.values())  # 105

        covered_count = await session.scalar(
            select(func.count(func.distinct(Detection.technique_id))).where(
                Detection.technique_id.is_not(None)
            )
        ) or 0

        if covered_count == 0:
            return None

        covered_count = min(covered_count, total_count)
        coverage_pct = round(covered_count / total_count * 100, 1)

        return {
            "coverage_pct": coverage_pct,
            "covered_count": covered_count,
            "total_count": total_count,
        }

    @staticmethod
    async def get_heatmap(session: AsyncSession) -> list[dict]:
        """Build heatmap coverage from distinct (technique_id, tactic) detection pairs.

        For each of the 4 top technique families × 9 tactic columns:
          covered = # distinct sub-technique IDs detected for that family+tactic
          total   = fixed ATT&CK v14 sub-technique count for that tactic column

        Always returns the full 4 × 9 grid; every cell has ``covered == 0`` when
        no detections exist.
        """
        q = (
            select(Detection.technique_id, Detection.tactic)
            .where(Detection.technique_id.is_not(None))
            .where(Detection.tactic.is_not(None))
            .distinct()
        )
        result = await session.execute(q)
        rows = result.all()

        # Build coverage sets: {family: {label: set_of_covered_technique_ids}}
        coverage: dict[str, dict[str, set]] = {
            family: {label: set() for label in TACTIC_LABELS}
            for family in _HEATMAP_TECHNIQUE_FAMILIES
        }

        for technique_id, tactic in rows:
            label = _TACTIC_LABEL_MAP.get(tactic_name(tactic))
            if not label:
                continue
            for family in _HEATMAP_TECHNIQUE_FAMILIES:
                if technique_id.startswith(family):
                    coverage[family][label].add(technique_id)

        heatmap: list[dict] = []
        for row_idx, family in enumerate(_HEATMAP_TECHNIQUE_FAMILIES):
            cells = [
                {
                    "tactic": label,
                    "covered": min(len(coverage[family][label]), _TACTIC_TOTALS.get(label, 10)),
                    "total": _TACTIC_TOTALS.get(label, 10),
                }
                for label in TACTIC_LABELS
            ]
            heatmap.append({"technique_id": family, "row": row_idx, "cells": cells})

        return heatmap

    @staticmethod
    async def count_recent_by_rule_host(
        session: AsyncSession,
        *,
        rule_name: str,
        host: str,
        window_seconds: int = 86400,
    ) -> int:
        """Count detections with the same rule_name and host within the last window_seconds.

        Used by the recurrence bonus scoring (feature 9.6): a higher occurrence count
        in the lookback window drives a higher recurrence_bonus (capped at 1.0 for 10+
        occurrences).
        """
        from_time = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
        result = await session.scalar(
            select(func.count())
            .select_from(Detection)
            .where(Detection.rule_name == rule_name)
            .where(Detection.host == host)
            .where(Detection.time >= from_time)
        )
        return int(result or 0)

    @staticmethod
    async def get_timeline(
        session: AsyncSession,
        *,
        from_date: datetime,
        to_date: datetime,
    ) -> list[dict]:
        """Return daily detection counts grouped by severity for a date range.

        Each returned dict has keys: day (YYYY-MM-DD str), critical, high, medium, total.
        Only days that have at least one detection are included; the caller fills gaps.
        """
        q = (
            select(
                func.date(Detection.time).label("day"),
                func.sum(case((Detection.severity == "critical", 1), else_=0)).label("critical"),
                func.sum(case((Detection.severity == "high", 1), else_=0)).label("high"),
                func.sum(case((Detection.severity == "medium", 1), else_=0)).label("medium"),
                func.count().label("total"),
            )
            .where(Detection.time >= from_date)
            .where(Detection.time <= to_date)
            .group_by(func.date(Detection.time))
            .order_by(func.date(Detection.time))
        )
        result = await session.execute(q)
        return [
            {
                "day": str(row.day),
                "critical": int(row.critical or 0),
                "high": int(row.high or 0),
                "medium": int(row.medium or 0),
                "total": int(row.total),
            }
            for row in result.all()
        ]
