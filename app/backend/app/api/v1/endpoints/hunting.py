"""ATT&CK-guided hunting suggestions endpoint (Feature 11.8).

GET /hunting/suggestions
    Returns a ranked list of hunt suggestions derived from:
      - Recent detection telemetry (trending ATT&CK techniques)
      - Coverage gap analysis (techniques in the rule library but not enabled)

    Requires detections:read permission (analyst role and above).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ....core.database import get_db
from ....core.rbac import require_permission
from ....schemas.hunting import HuntSuggestionsResponse
from ....services.hunt_suggestions import get_hunt_suggestions

router = APIRouter(prefix="/hunting", tags=["hunting"])


@router.get("/suggestions", response_model=HuntSuggestionsResponse)
async def get_hunting_suggestions(
    hours: Annotated[
        int,
        Query(ge=1, le=720, description="Detection analysis window in hours (1–720, default 24)"),
    ] = 24,
    limit: Annotated[
        int,
        Query(ge=1, le=50, description="Maximum number of suggestions to return (1–50, default 10)"),
    ] = 10,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_permission("detections:read")),
) -> HuntSuggestionsResponse:
    """Return ATT&CK-guided hunt suggestions ranked by analyst urgency.

    Suggestions are derived from two signals:

    1. **Trending techniques** — ATT&CK techniques with elevated detection
       counts in the requested time window.  High critical/high-severity
       activity or a lack of rule coverage elevates the priority to "high".

    2. **Coverage gaps** — techniques present in the Sigma rule library
       (enabled or disabled) but not covered by any *enabled* rule.  These
       are blind spots where manual hunting compensates for missing automation.

    Each suggestion includes:
    - The ATT&CK technique and tactic context
    - A human-readable reason explaining why it was surfaced
    - A priority hint ("high" | "medium" | "low")
    - Ready-to-run hunt queries the analyst can load with one click

    Query parameters:
    - ``hours``  — look-back window for detection activity (default 24, max 720)
    - ``limit``  — maximum suggestions returned (default 10, max 50)
    """
    return await get_hunt_suggestions(db, hours=hours, limit=limit)
