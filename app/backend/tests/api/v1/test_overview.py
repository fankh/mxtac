"""Tests for GET /api/v1/overview/* endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_kpis(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/overview/kpis", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_detections" in data
    assert "critical_alerts" in data
    assert "attack_covered" in data
    assert "sigma_rules_active" in data


# ---------------------------------------------------------------------------
# Feature 28.38 — KPIs return expected shape
# ---------------------------------------------------------------------------

_KPI_INT_FIELDS = [
    "total_detections",
    "critical_alerts",
    "critical_alerts_new_today",
    "attack_covered",
    "attack_total",
    "attack_coverage_delta",
    "integrations_active",
    "integrations_total",
    "sigma_rules_active",
    "sigma_rules_critical",
    "sigma_rules_high",
    "sigma_rules_deployed_this_week",
    "open_incidents_count",
]

_KPI_FLOAT_FIELDS = [
    "total_detections_delta_pct",
    "attack_coverage_pct",
    "mttd_minutes",
    "mttd_delta_minutes",
]


@pytest.mark.asyncio
async def test_kpis_shape_all_fields_present(client: AsyncClient, auth_headers: dict) -> None:
    """All 18 KPI fields must be present in the response."""
    resp = await client.get("/api/v1/overview/kpis", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    expected_fields = set(_KPI_INT_FIELDS) | set(_KPI_FLOAT_FIELDS) | {"mttr_minutes"}
    missing = expected_fields - set(data.keys())
    assert not missing, f"KPI response missing fields: {missing}"


@pytest.mark.asyncio
async def test_kpis_shape_int_fields_are_int(client: AsyncClient, auth_headers: dict) -> None:
    """Integer KPI fields must be JSON integers (not floats)."""
    resp = await client.get("/api/v1/overview/kpis", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    for field in _KPI_INT_FIELDS:
        value = data[field]
        assert isinstance(value, int), (
            f"Field '{field}' should be int, got {type(value).__name__} = {value!r}"
        )


@pytest.mark.asyncio
async def test_kpis_shape_float_fields_are_numeric(client: AsyncClient, auth_headers: dict) -> None:
    """Float KPI fields must be JSON numbers (int or float — both are valid JSON numbers)."""
    resp = await client.get("/api/v1/overview/kpis", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    for field in _KPI_FLOAT_FIELDS:
        value = data[field]
        assert isinstance(value, (int, float)), (
            f"Field '{field}' should be numeric, got {type(value).__name__} = {value!r}"
        )


@pytest.mark.asyncio
async def test_kpis_shape_value_constraints(client: AsyncClient, auth_headers: dict) -> None:
    """KPI values must satisfy logical constraints."""
    resp = await client.get("/api/v1/overview/kpis", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    # Non-negative counts
    for field in _KPI_INT_FIELDS:
        assert data[field] >= 0, f"Field '{field}' must be >= 0, got {data[field]}"

    # Coverage percentage in [0, 100]
    assert 0.0 <= data["attack_coverage_pct"] <= 100.0, (
        f"attack_coverage_pct={data['attack_coverage_pct']} out of [0, 100]"
    )

    # Covered techniques cannot exceed total
    assert data["attack_covered"] <= data["attack_total"], (
        f"attack_covered={data['attack_covered']} > attack_total={data['attack_total']}"
    )

    # Active integrations cannot exceed total
    assert data["integrations_active"] <= data["integrations_total"], (
        f"integrations_active={data['integrations_active']} > integrations_total={data['integrations_total']}"
    )

    # MTTD must be non-negative
    assert data["mttd_minutes"] >= 0, (
        f"mttd_minutes={data['mttd_minutes']} must be >= 0"
    )

    # Critical alerts cannot exceed total detections
    assert data["critical_alerts"] <= data["total_detections"], (
        f"critical_alerts={data['critical_alerts']} > total_detections={data['total_detections']}"
    )


@pytest.mark.asyncio
async def test_kpis_shape_mttr_is_null_when_no_incidents(
    client: AsyncClient, auth_headers: dict
) -> None:
    """mttr_minutes must be null when no incident resolution data exists (empty DB)."""
    resp = await client.get("/api/v1/overview/kpis", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    # With an empty DB there are no resolved incidents, so MTTR cannot be computed.
    assert data["mttr_minutes"] is None, (
        f"Expected mttr_minutes=null with empty DB, got {data['mttr_minutes']!r}"
    )


@pytest.mark.asyncio
async def test_kpis_shape_attack_total_positive(client: AsyncClient, auth_headers: dict) -> None:
    """attack_total must always be a positive constant (ATT&CK scope ≥ 1)."""
    resp = await client.get("/api/v1/overview/kpis", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["attack_total"] > 0, "attack_total must be a positive constant"


@pytest.mark.asyncio
async def test_kpis_range_param_accepted(client: AsyncClient, auth_headers: dict) -> None:
    """The range query parameter is accepted for all valid values; shape is consistent."""
    for range_val in ("24h", "7d", "30d", "90d"):
        resp = await client.get(
            f"/api/v1/overview/kpis?range={range_val}", headers=auth_headers
        )
        assert resp.status_code == 200, f"Failed for range={range_val}"
        data = resp.json()
        # Core fields must always be present regardless of range
        for field in ("total_detections", "critical_alerts", "attack_coverage_pct", "sigma_rules_active"):
            assert field in data, f"Field '{field}' missing for range={range_val}"


@pytest.mark.asyncio
async def test_timeline(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/overview/timeline", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) > 0
    assert "date" in items[0]
    assert "total" in items[0]
    assert "critical" in items[0]


@pytest.mark.asyncio
async def test_tactics(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/overview/tactics", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) > 0
    assert "tactic" in items[0]
    assert "count" in items[0]
    assert "trend_pct" in items[0]


@pytest.mark.asyncio
async def test_tactics_range_param(client: AsyncClient, auth_headers: dict) -> None:
    for range_val in ("24h", "7d", "30d", "90d"):
        resp = await client.get(
            f"/api/v1/overview/tactics?range={range_val}", headers=auth_headers
        )
        assert resp.status_code == 200, f"Failed for range={range_val}"


@pytest.mark.asyncio
async def test_heatmap(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    assert resp.status_code == 200
    rows = resp.json()
    assert isinstance(rows, list)
    assert len(rows) > 0
    first_row = rows[0]
    assert "row" in first_row
    assert "technique_id" in first_row
    assert "cells" in first_row
    assert len(first_row["cells"]) > 0
    first_cell = first_row["cells"][0]
    assert "tactic" in first_cell
    assert "covered" in first_cell
    assert "total" in first_cell
    assert "opacity" in first_cell
    assert isinstance(first_cell["opacity"], float)


@pytest.mark.asyncio
async def test_tactic_labels(client: AsyncClient, auth_headers: dict) -> None:
    resp = await client.get("/api/v1/overview/coverage/tactic-labels", headers=auth_headers)
    assert resp.status_code == 200
    labels = resp.json()
    assert isinstance(labels, list)
    assert len(labels) > 0
    assert all(isinstance(label, str) for label in labels)


@pytest.mark.asyncio
async def test_integrations(client: AsyncClient, auth_headers: dict) -> None:
    """Empty DB falls back to mock data (>0 items with required fields)."""
    resp = await client.get("/api/v1/overview/integrations", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) > 0
    assert "id" in items[0]
    assert "name" in items[0]
    assert "status" in items[0]
    assert "metric" in items[0]
    assert items[0]["status"] in ("connected", "warning", "disabled")


@pytest.mark.asyncio
async def test_integrations_from_db(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """When connectors exist in DB, endpoint returns real data (not mock)."""
    from app.models.connector import Connector

    active = Connector(
        name="Wazuh SIEM",
        connector_type="wazuh",
        status="active",
        enabled=True,
        events_total=5000,
    )
    warning = Connector(
        name="Splunk",
        connector_type="generic",
        status="error",
        enabled=True,
        events_total=0,
        error_message="Token expired",
    )
    disabled = Connector(
        name="OpenCTI",
        connector_type="opencti",
        status="inactive",
        enabled=False,
        events_total=0,
    )
    db_session.add_all([active, warning, disabled])
    await db_session.flush()

    resp = await client.get("/api/v1/overview/integrations", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) == 3

    by_name = {i["name"]: i for i in items}

    assert by_name["Wazuh SIEM"]["status"] == "connected"
    assert "5,000" in by_name["Wazuh SIEM"]["metric"]

    assert by_name["Splunk"]["status"] == "warning"
    assert by_name["Splunk"]["detail"] == "Token expired"

    assert by_name["OpenCTI"]["status"] == "disabled"


@pytest.mark.asyncio
async def test_recent_detections(client: AsyncClient, auth_headers: dict) -> None:
    """Empty DB falls back to mock data — only critical/high, at most 6 items."""
    resp = await client.get("/api/v1/overview/recent-detections", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) <= 6
    for item in items:
        assert item["severity"] in ("critical", "high")
        assert "id" in item
        assert "name" in item
        assert "host" in item
        assert "tactic" in item
        assert "time" in item
        assert "score" in item


@pytest.mark.asyncio
async def test_recent_detections_limit(client: AsyncClient, auth_headers: dict) -> None:
    """?limit param is respected."""
    resp = await client.get(
        "/api/v1/overview/recent-detections?limit=3", headers=auth_headers
    )
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) <= 3


@pytest.mark.asyncio
async def test_kpis_from_db(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """When detections + connectors + rules exist in DB, KPI returns real counts."""
    from datetime import datetime, timezone
    from app.models.detection import Detection as DetectionModel
    from app.models.connector import Connector
    from app.models.rule import Rule

    now = datetime.now(timezone.utc)
    det = DetectionModel(
        score=9.5,
        severity="critical",
        technique_id="T1059.001",
        technique_name="PowerShell",
        name="Critical Detection",
        host="host-a",
        tactic="Execution",
        tactic_id="TA0002",
        status="active",
        time=now,
        description="test",
        user="root",
        process="pwsh",
        rule_name="rule1",
        log_source="syslog",
        event_id="evt1",
        occurrence_count=1,
        cvss_v3=9.0,
        confidence=90,
        assigned_to=None,
        priority="P1",
    )
    conn = Connector(
        name="Wazuh",
        connector_type="wazuh",
        status="active",
        enabled=True,
        events_total=1000,
    )
    rule = Rule(
        title="PowerShell Encoded",
        content="detection: ...",
        level="critical",
        enabled=True,
        technique_ids='["T1059.001"]',
        tactic_ids='["TA0002"]',
    )
    db_session.add_all([det, conn, rule])
    await db_session.flush()

    resp = await client.get("/api/v1/overview/kpis", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    # Real detection counts
    assert data["total_detections"] == 1
    assert data["critical_alerts"] == 1

    # Real connector counts
    assert data["integrations_total"] == 1
    assert data["integrations_active"] == 1

    # Real rule counts
    assert data["sigma_rules_active"] == 1
    assert data["sigma_rules_critical"] == 1
    assert data["sigma_rules_high"] == 0
    assert data["sigma_rules_deployed_this_week"] == 1


@pytest.mark.asyncio
async def test_heatmap_from_db(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """When detections exist in DB, heatmap returns real coverage data (not mock)."""
    from datetime import datetime, timezone
    from app.models.detection import Detection as DetectionModel

    now = datetime.now(timezone.utc)
    rows = [
        DetectionModel(
            score=9.0,
            severity="critical",
            technique_id="T1059.001",  # sub-technique of T1059
            technique_name="PowerShell",
            name="PowerShell Execution",
            host="host-a",
            tactic="Execution",  # maps to EXEC column
            tactic_id="TA0002",
            status="active",
            time=now,
            description="test",
            user="root",
            process="pwsh",
            rule_name="rule1",
            log_source="syslog",
            event_id="evt1",
            occurrence_count=1,
            cvss_v3=9.0,
            confidence=90,
            assigned_to=None,
            priority="P1",
        ),
        DetectionModel(
            score=8.0,
            severity="high",
            technique_id="T1059.003",  # another T1059 sub-technique
            technique_name="Windows Command Shell",
            name="CMD Execution",
            host="host-b",
            tactic="Execution",
            tactic_id="TA0002",
            status="active",
            time=now,
            description="test",
            user="user1",
            process="cmd.exe",
            rule_name="rule2",
            log_source="syslog",
            event_id="evt2",
            occurrence_count=1,
            cvss_v3=8.0,
            confidence=85,
            assigned_to=None,
            priority="P2",
        ),
        DetectionModel(
            score=7.0,
            severity="high",
            technique_id="T1059.001",  # duplicate — only counted once (DISTINCT)
            technique_name="PowerShell",
            name="PowerShell Again",
            host="host-c",
            tactic="Execution",
            tactic_id="TA0002",
            status="active",
            time=now,
            description="test",
            user="user2",
            process="pwsh.exe",
            rule_name="rule3",
            log_source="syslog",
            event_id="evt3",
            occurrence_count=2,
            cvss_v3=7.0,
            confidence=80,
            assigned_to=None,
            priority="P2",
        ),
    ]
    db_session.add_all(rows)
    await db_session.flush()

    resp = await client.get("/api/v1/overview/coverage/heatmap", headers=auth_headers)
    assert resp.status_code == 200
    heatmap = resp.json()

    # Should be 4 rows (one per technique family)
    assert len(heatmap) == 4

    # Row 0 is T1059 — find it
    t1059_row = next((r for r in heatmap if r["technique_id"] == "T1059"), None)
    assert t1059_row is not None

    # EXEC column (Execution tactic) should have covered=2 (T1059.001 and T1059.003)
    exec_cell = next((c for c in t1059_row["cells"] if c["tactic"] == "EXEC"), None)
    assert exec_cell is not None
    assert exec_cell["covered"] == 2  # distinct: T1059.001, T1059.003
    assert exec_cell["total"] == 14   # fixed ATT&CK total for EXEC

    # CRED column should have covered=0 (no Credential Access detections)
    cred_cell = next((c for c in t1059_row["cells"] if c["tactic"] == "CRED"), None)
    assert cred_cell is not None
    assert cred_cell["covered"] == 0

    # opacity is computed
    assert isinstance(exec_cell["opacity"], float)


@pytest.mark.asyncio
async def test_recent_detections_from_db(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """When DB has detections, endpoint returns real data — only critical/high, sorted newest first."""
    from datetime import datetime, timezone
    from app.models.detection import Detection as DetectionModel

    now = datetime.now(timezone.utc)
    rows = [
        DetectionModel(
            score=9.5,
            severity="critical",
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            name="Critical Alert",
            host="host-a",
            tactic="execution",
            tactic_id="TA0002",
            status="active",
            time=now,
            description="test",
            user="root",
            process="bash",
            rule_name="rule1",
            log_source="syslog",
            event_id="evt1",
            occurrence_count=1,
            cvss_v3=9.0,
            confidence=90,
            assigned_to="analyst",
            priority="P1",
        ),
        DetectionModel(
            score=7.0,
            severity="high",
            technique_id="T1078",
            technique_name="Valid Accounts",
            name="High Alert",
            host="host-b",
            tactic="persistence",
            tactic_id="TA0003",
            status="investigating",
            time=now,
            description="test",
            user="user1",
            process="sshd",
            rule_name="rule2",
            log_source="auth",
            event_id="evt2",
            occurrence_count=2,
            cvss_v3=7.0,
            confidence=80,
            assigned_to=None,
            priority="P2",
        ),
        DetectionModel(
            score=3.0,
            severity="medium",
            technique_id="T1110",
            technique_name="Brute Force",
            name="Medium Alert",
            host="host-c",
            tactic="credential_access",
            tactic_id="TA0006",
            status="active",
            time=now,
            description="test",
            user="user2",
            process="login",
            rule_name="rule3",
            log_source="auth",
            event_id="evt3",
            occurrence_count=5,
            cvss_v3=5.0,
            confidence=60,
            assigned_to=None,
            priority="P3",
        ),
    ]
    db_session.add_all(rows)
    await db_session.flush()

    resp = await client.get("/api/v1/overview/recent-detections", headers=auth_headers)
    assert resp.status_code == 200
    items = resp.json()

    # Only critical and high — medium is excluded
    assert len(items) == 2
    severities = {i["severity"] for i in items}
    assert severities <= {"critical", "high"}
    assert "medium" not in severities
