"""Detection repository — async DB operations for the detections table."""

from __future__ import annotations

from datetime import datetime
from math import ceil

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.detection import Detection

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

_HEATMAP_ORDERED_LABELS = ["RECON", "RES", "INIT", "EXEC", "PERS", "PRIV", "DEF-E", "CRED", "DISC"]
_HEATMAP_TECHNIQUE_FAMILIES = ["T1059", "T1003", "T1021", "T1078"]


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
            q = q.where(Detection.tactic.ilike(f"%{tactic}%"))
        if host:
            q = q.where(Detection.host.ilike(f"%{host}%"))
        if search:
            pattern = f"%{search}%"
            q = q.where(
                Detection.name.ilike(pattern)
                | Detection.description.ilike(pattern)
                | Detection.technique_id.ilike(pattern)
                | Detection.host.ilike(pattern)
            )

        # Count
        count_q = select(func.count()).select_from(q.subquery())
        total = await session.scalar(count_q) or 0

        # Sort
        sort_col = getattr(Detection, sort, Detection.time)
        q = q.order_by(sort_col.desc() if order == "desc" else sort_col.asc())

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
        current_rows = {row.tactic: int(row.count) for row in current_result.all()}

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
        prev_rows = {row.tactic: int(row.count) for row in prev_result.all()}

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
    async def get_heatmap(session: AsyncSession) -> list[dict] | None:
        """Build heatmap coverage from distinct (technique_id, tactic) detection pairs.

        For each of the 4 top technique families × 9 tactic columns:
          covered = # distinct sub-technique IDs detected for that family+tactic
          total   = fixed ATT&CK v14 sub-technique count for that tactic column

        Returns None when no detections exist (caller should fall back to mock).
        """
        q = (
            select(Detection.technique_id, Detection.tactic)
            .where(Detection.technique_id.is_not(None))
            .where(Detection.tactic.is_not(None))
            .distinct()
        )
        result = await session.execute(q)
        rows = result.all()

        if not rows:
            return None

        # Build coverage sets: {family: {label: set_of_covered_technique_ids}}
        coverage: dict[str, dict[str, set]] = {
            family: {label: set() for label in _HEATMAP_ORDERED_LABELS}
            for family in _HEATMAP_TECHNIQUE_FAMILIES
        }

        for technique_id, tactic in rows:
            label = _TACTIC_LABEL_MAP.get(tactic)
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
                for label in _HEATMAP_ORDERED_LABELS
            ]
            heatmap.append({"technique_id": family, "row": row_idx, "cells": cells})

        return heatmap

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
