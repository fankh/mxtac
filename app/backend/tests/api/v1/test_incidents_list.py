"""Tests for Feature 26.4 — GET /incidents — paginated list with filters.

Verifies:
- Empty DB returns empty list with correct pagination envelope.
- Items include all expected Incident fields.
- page / page_size params are respected; total / total_pages are accurate.
- severity filter (single + multi-value) narrows results.
- status filter (single + multi-value) narrows results.
- assigned_to filter matches exact email.
- search param matches title and description (case-insensitive).
- sort=created_at (default) orders newest first.
- sort=severity orders critical → high → medium → low.
- sort=status orders new → investigating → contained → resolved → closed.
- Viewer+ role can access (incidents:read); unauthenticated gets 401.
- Invalid query params return 422.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_INCIDENT = {
    "title": "Test Incident",
    "description": "Integration test incident.",
    "severity": "high",
    "detection_ids": [],
}


async def _create_incident(client: AsyncClient, headers: dict, **overrides) -> dict:
    body = {**_BASE_INCIDENT, **overrides}
    resp = await client.post("/api/v1/incidents", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _list_incidents(client: AsyncClient, headers: dict, **params) -> dict:
    resp = await client.get("/api/v1/incidents", params=params, headers=headers)
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Response structure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_db_returns_empty_list(client: AsyncClient, viewer_headers: dict) -> None:
    """Empty database returns an empty list with page=1, total=0."""
    data = await _list_incidents(client, viewer_headers)

    assert data["items"] == []
    p = data["pagination"]
    assert p["total"] == 0
    assert p["page"] == 1
    assert p["page_size"] == 20
    assert p["total_pages"] == 1  # min=1


@pytest.mark.asyncio
async def test_response_contains_expected_fields(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Each item in 'items' contains all expected Incident fields."""
    await _create_incident(
        client,
        analyst_headers,
        title="Field Check Incident",
        description="Checking fields.",
        severity="medium",
    )

    data = await _list_incidents(client, viewer_headers)
    assert len(data["items"]) == 1
    item = data["items"][0]

    expected_fields = {
        "id", "title", "description", "severity", "status", "priority",
        "assigned_to", "created_by", "detection_ids", "technique_ids",
        "tactic_ids", "hosts", "ttd_seconds", "ttr_seconds",
        "closed_at", "created_at", "updated_at",
    }
    assert expected_fields.issubset(item.keys())


@pytest.mark.asyncio
async def test_response_pagination_envelope(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Pagination envelope has correct page, page_size, total, total_pages."""
    for i in range(5):
        await _create_incident(client, analyst_headers, title=f"Incident {i}")

    data = await _list_incidents(client, viewer_headers, page=1, page_size=2)

    p = data["pagination"]
    assert p["total"] == 5
    assert p["page"] == 1
    assert p["page_size"] == 2
    assert p["total_pages"] == 3  # ceil(5/2)
    assert len(data["items"]) == 2


# ---------------------------------------------------------------------------
# Pagination — page / page_size
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pagination_second_page(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Second page returns remaining items."""
    for i in range(3):
        await _create_incident(client, analyst_headers, title=f"Incident {i}")

    page2 = await _list_incidents(client, viewer_headers, page=2, page_size=2)

    assert len(page2["items"]) == 1
    assert page2["pagination"]["page"] == 2


@pytest.mark.asyncio
async def test_pagination_page_beyond_end_returns_empty(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Requesting a page beyond total returns empty items list."""
    await _create_incident(client, analyst_headers)

    data = await _list_incidents(client, viewer_headers, page=99, page_size=20)

    assert data["items"] == []
    assert data["pagination"]["total"] == 1


@pytest.mark.asyncio
async def test_page_size_default_is_20(client: AsyncClient, viewer_headers: dict) -> None:
    """Default page_size is 20 when not specified."""
    data = await _list_incidents(client, viewer_headers)
    assert data["pagination"]["page_size"] == 20


@pytest.mark.asyncio
async def test_invalid_page_returns_422(client: AsyncClient, viewer_headers: dict) -> None:
    """page=0 is rejected with 422."""
    resp = await client.get("/api/v1/incidents", params={"page": 0}, headers=viewer_headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_invalid_page_size_too_large_returns_422(
    client: AsyncClient, viewer_headers: dict
) -> None:
    """page_size > 100 is rejected with 422."""
    resp = await client.get(
        "/api/v1/incidents", params={"page_size": 101}, headers=viewer_headers
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Filter — severity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_filter_severity_single(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Filtering by single severity returns only matching incidents."""
    await _create_incident(client, analyst_headers, severity="critical")
    await _create_incident(client, analyst_headers, severity="low")

    data = await _list_incidents(client, viewer_headers, severity="critical")

    assert data["pagination"]["total"] == 1
    assert data["items"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_filter_severity_multi(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Filtering by multiple severities returns all matching incidents."""
    await _create_incident(client, analyst_headers, severity="critical")
    await _create_incident(client, analyst_headers, severity="high")
    await _create_incident(client, analyst_headers, severity="low")

    resp = await client.get(
        "/api/v1/incidents",
        params=[("severity", "critical"), ("severity", "high")],
        headers=viewer_headers,
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["pagination"]["total"] == 2
    returned_severities = {item["severity"] for item in data["items"]}
    assert returned_severities == {"critical", "high"}


@pytest.mark.asyncio
async def test_filter_severity_no_match(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Severity filter with no match returns empty list."""
    await _create_incident(client, analyst_headers, severity="low")

    data = await _list_incidents(client, viewer_headers, severity="critical")

    assert data["items"] == []
    assert data["pagination"]["total"] == 0


# ---------------------------------------------------------------------------
# Filter — status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_filter_status_single(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Filtering by status='new' returns only new incidents."""
    inc = await _create_incident(client, analyst_headers)  # status=new
    # Advance second incident to investigating
    inc2 = await _create_incident(client, analyst_headers, title="Investigating Inc")
    await client.patch(
        f"/api/v1/incidents/{inc2['id']}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )

    data = await _list_incidents(client, viewer_headers, status="new")

    assert data["pagination"]["total"] == 1
    assert data["items"][0]["id"] == inc["id"]


@pytest.mark.asyncio
async def test_filter_status_multi(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Multiple status values are OR-combined."""
    new_inc = await _create_incident(client, analyst_headers, title="New Inc")
    inv_inc = await _create_incident(client, analyst_headers, title="Inv Inc")
    await client.patch(
        f"/api/v1/incidents/{inv_inc['id']}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )
    # Third incident stays 'new' to verify count
    await _create_incident(client, analyst_headers, title="Extra New")

    resp = await client.get(
        "/api/v1/incidents",
        params=[("status", "new"), ("status", "investigating")],
        headers=viewer_headers,
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["pagination"]["total"] == 3


# ---------------------------------------------------------------------------
# Filter — assigned_to
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_filter_assigned_to(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """assigned_to filter matches exact email."""
    await _create_incident(
        client, analyst_headers, title="Assigned", assigned_to="alice@corp.example"
    )
    await _create_incident(
        client, analyst_headers, title="Other", assigned_to="bob@corp.example"
    )
    await _create_incident(client, analyst_headers, title="Unassigned")

    data = await _list_incidents(client, viewer_headers, assigned_to="alice@corp.example")

    assert data["pagination"]["total"] == 1
    assert data["items"][0]["assigned_to"] == "alice@corp.example"


@pytest.mark.asyncio
async def test_filter_assigned_to_no_match(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """assigned_to filter with no match returns empty list."""
    await _create_incident(client, analyst_headers)

    data = await _list_incidents(client, viewer_headers, assigned_to="nobody@corp.example")

    assert data["items"] == []
    assert data["pagination"]["total"] == 0


# ---------------------------------------------------------------------------
# Filter — search (title + description)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_matches_title(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """search param filters by title substring (case-insensitive)."""
    await _create_incident(client, analyst_headers, title="SQL Injection Attack")
    await _create_incident(client, analyst_headers, title="Ransomware Outbreak")

    data = await _list_incidents(client, viewer_headers, search="sql injection")

    assert data["pagination"]["total"] == 1
    assert "SQL Injection" in data["items"][0]["title"]


@pytest.mark.asyncio
async def test_search_matches_description(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """search param matches description when title does not contain the term."""
    await _create_incident(
        client,
        analyst_headers,
        title="Lateral Movement Detected",
        description="Pass-the-hash technique observed on WS-CORP-42",
    )
    await _create_incident(
        client,
        analyst_headers,
        title="Unrelated Incident",
        description="Nothing suspicious here",
    )

    data = await _list_incidents(client, viewer_headers, search="pass-the-hash")

    assert data["pagination"]["total"] == 1
    assert data["items"][0]["title"] == "Lateral Movement Detected"


@pytest.mark.asyncio
async def test_search_case_insensitive(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """search is case-insensitive."""
    await _create_incident(client, analyst_headers, title="Phishing Campaign Alpha")

    data = await _list_incidents(client, viewer_headers, search="PHISHING CAMPAIGN")

    assert data["pagination"]["total"] == 1


@pytest.mark.asyncio
async def test_search_no_match_returns_empty(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """search with no match returns empty list."""
    await _create_incident(client, analyst_headers, title="Brute Force Login")

    data = await _list_incidents(client, viewer_headers, search="cryptomining")

    assert data["items"] == []


# ---------------------------------------------------------------------------
# Sort — created_at (default), severity, status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sort_created_at_desc_is_default(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Default sort returns incidents with created_at in descending order (newest first)."""
    await _create_incident(client, analyst_headers, title="First Created")
    await _create_incident(client, analyst_headers, title="Second Created")
    await _create_incident(client, analyst_headers, title="Third Created")

    data = await _list_incidents(client, viewer_headers)
    timestamps = [item["created_at"] for item in data["items"]]

    # Verify timestamps are in non-ascending order (newest first)
    assert timestamps == sorted(timestamps, reverse=True)


@pytest.mark.asyncio
async def test_sort_severity(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """sort=severity orders: critical → high → medium → low."""
    await _create_incident(client, analyst_headers, title="Low", severity="low")
    await _create_incident(client, analyst_headers, title="Critical", severity="critical")
    await _create_incident(client, analyst_headers, title="Medium", severity="medium")

    data = await _list_incidents(client, viewer_headers, sort="severity")
    severities = [item["severity"] for item in data["items"]]

    assert severities.index("critical") < severities.index("medium")
    assert severities.index("medium") < severities.index("low")


@pytest.mark.asyncio
async def test_sort_status(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """sort=status orders: new → investigating → ... → closed."""
    inc_new = await _create_incident(client, analyst_headers, title="New Inc")
    inc_inv = await _create_incident(client, analyst_headers, title="Inv Inc")
    await client.patch(
        f"/api/v1/incidents/{inc_inv['id']}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )
    # Advance third to contained
    inc_cont = await _create_incident(client, analyst_headers, title="Cont Inc")
    for s in ("investigating", "contained"):
        await client.patch(
            f"/api/v1/incidents/{inc_cont['id']}",
            json={"status": s},
            headers=analyst_headers,
        )

    data = await _list_incidents(client, viewer_headers, sort="status")
    statuses = [item["status"] for item in data["items"]]

    assert statuses.index("new") < statuses.index("investigating")
    assert statuses.index("investigating") < statuses.index("combined" if False else "contained")


@pytest.mark.asyncio
async def test_invalid_sort_returns_422(client: AsyncClient, viewer_headers: dict) -> None:
    """An unrecognized sort value is rejected with 422."""
    resp = await client.get(
        "/api/v1/incidents", params={"sort": "nonexistent_field"}, headers=viewer_headers
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# RBAC — authorization
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewer_can_list_incidents(client: AsyncClient, viewer_headers: dict) -> None:
    """Viewer role (incidents:read) can access the list endpoint."""
    resp = await client.get("/api/v1/incidents", headers=viewer_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_analyst_can_list_incidents(client: AsyncClient, analyst_headers: dict) -> None:
    """Analyst role can list incidents."""
    resp = await client.get("/api/v1/incidents", headers=analyst_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_admin_can_list_incidents(client: AsyncClient, admin_headers: dict) -> None:
    """Admin role can list incidents."""
    resp = await client.get("/api/v1/incidents", headers=admin_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_unauthenticated_cannot_list_incidents(client: AsyncClient) -> None:
    """Unauthenticated request returns 401."""
    resp = await client.get("/api/v1/incidents")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Combined filters
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_combined_severity_and_status_filter(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Combining severity + status filters narrows results to exact intersection."""
    # critical+new — should match
    await _create_incident(client, analyst_headers, title="Match", severity="critical")
    # high+new — severity mismatch
    await _create_incident(client, analyst_headers, title="High New", severity="high")
    # critical+investigating — status mismatch
    inc = await _create_incident(
        client, analyst_headers, title="Critical Inv", severity="critical"
    )
    await client.patch(
        f"/api/v1/incidents/{inc['id']}",
        json={"status": "investigating"},
        headers=analyst_headers,
    )

    resp = await client.get(
        "/api/v1/incidents",
        params=[("severity", "critical"), ("status", "new")],
        headers=viewer_headers,
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["pagination"]["total"] == 1
    item = data["items"][0]
    assert item["severity"] == "critical"
    assert item["status"] == "new"


@pytest.mark.asyncio
async def test_combined_search_and_severity_filter(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Search combined with severity filter intersects both conditions."""
    await _create_incident(
        client, analyst_headers, title="APT29 Exfiltration", severity="critical"
    )
    await _create_incident(
        client, analyst_headers, title="APT29 Persistence", severity="low"
    )
    await _create_incident(
        client, analyst_headers, title="Brute Force Attack", severity="critical"
    )

    resp = await client.get(
        "/api/v1/incidents",
        params=[("search", "APT29"), ("severity", "critical")],
        headers=viewer_headers,
    )
    assert resp.status_code == 200
    data = resp.json()

    assert data["pagination"]["total"] == 1
    assert "APT29" in data["items"][0]["title"]
    assert data["items"][0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# Incident content fields
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_returns_correct_field_values(
    client: AsyncClient, analyst_headers: dict, viewer_headers: dict
) -> None:
    """Listed incident preserves title, severity, status, created_by, and assigned_to."""
    await _create_incident(
        client,
        analyst_headers,
        title="Specific Incident",
        description="Detailed description.",
        severity="critical",
        assigned_to="responder@corp.example",
    )

    data = await _list_incidents(client, viewer_headers)
    item = data["items"][0]

    assert item["title"] == "Specific Incident"
    assert item["description"] == "Detailed description."
    assert item["severity"] == "critical"
    assert item["status"] == "new"
    assert item["created_by"] == "analyst@mxtac.local"
    assert item["assigned_to"] == "responder@corp.example"
