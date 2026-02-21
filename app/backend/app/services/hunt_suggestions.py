"""ATT&CK-guided hunt suggestions service (Feature 11.8).

Generates ranked hunt suggestions by analysing:
  1. Trending techniques — techniques with many recent detections that warrant
     deeper investigation (the detections may be the tip of the iceberg).
  2. Coverage-gap techniques — techniques present in the rule library (even in
     disabled rules) but with no enabled rule coverage; these are blind spots
     where manual hunting can compensate for missing automation.

Priority assignment:
  "high"   — ≥1 critical-severity detection  OR  trending technique with no rule coverage
  "medium" — ≥1 high-severity detection  OR  trending technique with ≥1 rule
  "low"    — coverage-gap technique with no recent detections
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..repositories.detection_repo import DetectionRepo
from ..repositories.rule_repo import RuleRepo
from ..schemas.hunting import HuntSuggestion, HuntSuggestionsResponse, SuggestedQuery

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PRIORITY_HIGH   = "high"
_PRIORITY_MEDIUM = "medium"
_PRIORITY_LOW    = "low"

# Number of coverage-gap techniques to surface (keep UI concise)
_GAP_LIMIT = 5


def _make_queries(technique_id: str, technique_name: str, tactic: str, time_from: str) -> list[SuggestedQuery]:
    """Build suggested hunt queries for a technique."""
    return [
        SuggestedQuery(
            label=f"Hunt {technique_id}: {technique_name}",
            query=technique_id,
            time_from=time_from,
        ),
        SuggestedQuery(
            label=f"All {tactic} activity",
            query=tactic,
            time_from=time_from,
        ),
    ]


def _assign_priority(count: int, critical: int, high: int, rule_count: int) -> str:
    """Derive the urgency priority for a suggestion."""
    if critical > 0 or (count > 0 and rule_count == 0):
        return _PRIORITY_HIGH
    if high > 0 or count > 0:
        return _PRIORITY_MEDIUM
    return _PRIORITY_LOW


def _build_reason(count: int, critical: int, high: int, rule_count: int, is_gap: bool) -> str:
    """Write a one-line reason explaining why this technique is surfaced."""
    if is_gap:
        if count > 0:
            return (
                f"{count} detection{'s' if count != 1 else ''} in window with no active rule "
                f"coverage — manual hunting recommended"
            )
        return "No active Sigma rule coverage — technique is a blind spot; manual hunting required"
    parts: list[str] = []
    if count:
        parts.append(f"{count} detection{'s' if count != 1 else ''} in analysis window")
    if critical:
        parts.append(f"{critical} critical-severity")
    if high:
        parts.append(f"{high} high-severity")
    if rule_count == 0:
        parts.append("no active rule coverage")
    elif rule_count == 1:
        parts.append("1 active rule")
    else:
        parts.append(f"{rule_count} active rules")
    return "; ".join(parts) if parts else "Trending technique detected"


async def get_hunt_suggestions(
    db: AsyncSession,
    *,
    hours: int = 24,
    limit: int = 10,
) -> HuntSuggestionsResponse:
    """Generate ATT&CK-guided hunt suggestions for the given analysis window.

    Args:
        db:     Async database session.
        hours:  Look-back window for detection activity (default 24 h).
        limit:  Maximum number of suggestions to return (default 10).

    Returns:
        HuntSuggestionsResponse with ranked suggestions and metadata.
    """
    now = datetime.now(timezone.utc)
    from_date = now - timedelta(hours=hours)
    time_from = f"now-{hours}h"

    # ── 1. Recent detection activity per technique ────────────────────────────
    activity = await DetectionRepo.get_technique_activity(db, from_date=from_date, limit=50)

    # ── 2. Enabled rule counts per technique ─────────────────────────────────
    rule_counts = await RuleRepo.get_enabled_rule_counts_by_technique(db)

    # ── 3. Coverage gaps (techniques in any rule but not in enabled rules) ────
    gaps_data = await RuleRepo.get_coverage_gaps(db)
    uncovered = set(gaps_data.get("uncovered_techniques", []))

    # ── 4. Build suggestions from trending detections ─────────────────────────
    seen_techniques: set[str] = set()
    suggestions: list[HuntSuggestion] = []

    for row in activity:
        tid = row["technique_id"]
        if tid in seen_techniques:
            continue
        seen_techniques.add(tid)

        rule_count = rule_counts.get(tid, 0)
        count      = row["count"]
        critical   = row["critical"]
        high       = row["high"]
        is_gap     = tid in uncovered

        suggestions.append(
            HuntSuggestion(
                technique_id=tid,
                technique_name=row["technique_name"],
                tactic=row["tactic"],
                tactic_id=row["tactic_id"],
                reason=_build_reason(count, critical, high, rule_count, is_gap),
                priority=_assign_priority(count, critical, high, rule_count),
                detection_count=count,
                rule_count=rule_count,
                suggested_queries=_make_queries(tid, row["technique_name"], row["tactic"], time_from),
            )
        )

    # ── 5. Surface coverage-gap techniques not already included ───────────────
    gap_added = 0
    for tid in sorted(uncovered):
        if gap_added >= _GAP_LIMIT:
            break
        if tid in seen_techniques:
            continue
        seen_techniques.add(tid)
        gap_added += 1
        # We don't have tactic/name for pure gaps (only the technique ID from rules)
        suggestions.append(
            HuntSuggestion(
                technique_id=tid,
                technique_name=tid,      # fall back to ID when name is unknown
                tactic="Unknown",
                tactic_id="",
                reason=_build_reason(0, 0, 0, 0, is_gap=True),
                priority=_PRIORITY_LOW,
                detection_count=0,
                rule_count=0,
                suggested_queries=[
                    SuggestedQuery(
                        label=f"Hunt for {tid}",
                        query=tid,
                        time_from="now-7d",
                    )
                ],
            )
        )

    # ── 6. Sort: high → medium → low, then by detection_count desc ───────────
    _order = {_PRIORITY_HIGH: 0, _PRIORITY_MEDIUM: 1, _PRIORITY_LOW: 2}
    suggestions.sort(key=lambda s: (_order.get(s.priority, 3), -s.detection_count))

    return HuntSuggestionsResponse(
        suggestions=suggestions[:limit],
        generated_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        window_hours=hours,
    )
