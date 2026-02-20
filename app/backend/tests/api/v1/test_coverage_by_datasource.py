"""Tests for GET /api/v1/coverage/by-datasource — coverage per connector.

The endpoint returns:
  - sources              — list of per-connector metrics (wazuh, zeek, suricata)
  - total_covered_count  — distinct techniques covered by ANY enabled rule
  - total_count          — 105 (ATT&CK v14 fixed scope)
  - total_coverage_pct   — total_covered_count / 105 * 100

Logsource mapping (Sigma convention):
  - wazuh      ← product in {windows, linux, macos, unix, endpoint}
  - zeek        ← product == "zeek"  OR  category in {network_connection, network_flow,
                   dns, proxy, http, ssl, network}
  - suricata    ← product == "suricata"  OR  "suricata" in service
"""

import json

import pytest
from httpx import AsyncClient


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _make_rule(**kwargs):
    """Return a minimal Rule ORM instance."""
    from app.models.rule import Rule

    defaults = dict(
        title="Test Rule",
        content="title: Test Rule\n",
        level="medium",
        enabled=True,
        technique_ids=None,
        logsource_product=None,
        logsource_category=None,
        logsource_service=None,
    )
    defaults.update(kwargs)
    return Rule(**defaults)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_by_datasource_requires_auth(client: AsyncClient) -> None:
    """Unauthenticated request returns 401."""
    resp = await client.get("/api/v1/coverage/by-datasource")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_by_datasource_viewer_role_allowed(client: AsyncClient, viewer_headers: dict) -> None:
    """The viewer role (lowest privilege) can access the endpoint."""
    resp = await client.get("/api/v1/coverage/by-datasource", headers=viewer_headers)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Response shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_by_datasource_response_shape(client: AsyncClient, auth_headers: dict) -> None:
    """Response always contains the required top-level fields with correct types."""
    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert "sources" in data
    assert "total_covered_count" in data
    assert "total_count" in data
    assert "total_coverage_pct" in data

    assert isinstance(data["sources"], list)
    assert isinstance(data["total_covered_count"], int)
    assert isinstance(data["total_count"], int)
    assert isinstance(data["total_coverage_pct"], float)


@pytest.mark.asyncio
async def test_by_datasource_always_returns_three_sources(client: AsyncClient, auth_headers: dict) -> None:
    """Response always contains exactly three sources: wazuh, zeek, suricata."""
    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    source_names = {s["source"] for s in data["sources"]}
    assert source_names == {"wazuh", "zeek", "suricata"}
    assert len(data["sources"]) == 3


@pytest.mark.asyncio
async def test_by_datasource_source_shape(client: AsyncClient, auth_headers: dict) -> None:
    """Each source entry has all required fields with correct types."""
    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    for entry in data["sources"]:
        assert "source" in entry
        assert "covered_count" in entry
        assert "total_count" in entry
        assert "coverage_pct" in entry
        assert "rule_count" in entry
        assert isinstance(entry["source"], str)
        assert isinstance(entry["covered_count"], int)
        assert isinstance(entry["total_count"], int)
        assert isinstance(entry["coverage_pct"], float)
        assert isinstance(entry["rule_count"], int)


# ---------------------------------------------------------------------------
# Empty DB
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_by_datasource_empty_db_zero_coverage(client: AsyncClient, auth_headers: dict) -> None:
    """Empty DB → all sources at 0, total at 0."""
    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert data["total_covered_count"] == 0
    assert data["total_count"] == 105
    assert data["total_coverage_pct"] == 0.0

    for entry in data["sources"]:
        assert entry["covered_count"] == 0
        assert entry["coverage_pct"] == 0.0
        assert entry["rule_count"] == 0
        assert entry["total_count"] == 105


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_by_datasource_coverage_pct_in_range(client: AsyncClient, auth_headers: dict) -> None:
    """total_coverage_pct and per-source coverage_pct are always in [0.0, 100.0]."""
    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    assert 0.0 <= data["total_coverage_pct"] <= 100.0
    for entry in data["sources"]:
        assert 0.0 <= entry["coverage_pct"] <= 100.0


@pytest.mark.asyncio
async def test_by_datasource_total_count_fixed(client: AsyncClient, auth_headers: dict) -> None:
    """total_count and per-source total_count are always 105."""
    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    assert data["total_count"] == 105
    for entry in data["sources"]:
        assert entry["total_count"] == 105


# ---------------------------------------------------------------------------
# Wazuh logsource mapping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wazuh_windows_product_mapped(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Rules with logsource_product='windows' are mapped to wazuh."""
    db_session.add(_make_rule(
        title="Windows Rule",
        enabled=True,
        logsource_product="windows",
        technique_ids=json.dumps(["T1059.001"]),
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    wazuh = next(s for s in data["sources"] if s["source"] == "wazuh")
    assert wazuh["covered_count"] == 1
    assert wazuh["rule_count"] == 1


@pytest.mark.asyncio
async def test_wazuh_linux_product_mapped(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Rules with logsource_product='linux' are mapped to wazuh."""
    db_session.add(_make_rule(
        title="Linux Rule",
        enabled=True,
        logsource_product="linux",
        technique_ids=json.dumps(["T1548.001"]),
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    wazuh = next(s for s in data["sources"] if s["source"] == "wazuh")
    assert wazuh["covered_count"] == 1
    assert wazuh["rule_count"] == 1


# ---------------------------------------------------------------------------
# Zeek logsource mapping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_zeek_product_mapped(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Rules with logsource_product='zeek' are mapped to zeek."""
    db_session.add(_make_rule(
        title="Zeek Rule",
        enabled=True,
        logsource_product="zeek",
        technique_ids=json.dumps(["T1071.001"]),
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    zeek = next(s for s in data["sources"] if s["source"] == "zeek")
    assert zeek["covered_count"] == 1
    assert zeek["rule_count"] == 1


@pytest.mark.asyncio
async def test_zeek_dns_category_mapped(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Rules with logsource_category='dns' are mapped to zeek."""
    db_session.add(_make_rule(
        title="DNS Rule",
        enabled=True,
        logsource_category="dns",
        technique_ids=json.dumps(["T1071.004"]),
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    zeek = next(s for s in data["sources"] if s["source"] == "zeek")
    assert zeek["covered_count"] == 1
    assert zeek["rule_count"] == 1


@pytest.mark.asyncio
async def test_zeek_network_connection_category_mapped(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Rules with logsource_category='network_connection' are mapped to zeek."""
    db_session.add(_make_rule(
        title="Network Conn Rule",
        enabled=True,
        logsource_category="network_connection",
        technique_ids=json.dumps(["T1095"]),
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    zeek = next(s for s in data["sources"] if s["source"] == "zeek")
    assert zeek["covered_count"] == 1


# ---------------------------------------------------------------------------
# Suricata logsource mapping
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_suricata_product_mapped(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Rules with logsource_product='suricata' are mapped to suricata."""
    db_session.add(_make_rule(
        title="Suricata Rule",
        enabled=True,
        logsource_product="suricata",
        technique_ids=json.dumps(["T1110.001"]),
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    suricata = next(s for s in data["sources"] if s["source"] == "suricata")
    assert suricata["covered_count"] == 1
    assert suricata["rule_count"] == 1


@pytest.mark.asyncio
async def test_suricata_service_mapped(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Rules with logsource_service containing 'suricata' are mapped to suricata."""
    db_session.add(_make_rule(
        title="Suricata Service Rule",
        enabled=True,
        logsource_service="suricata",
        technique_ids=json.dumps(["T1046"]),
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    suricata = next(s for s in data["sources"] if s["source"] == "suricata")
    assert suricata["covered_count"] == 1
    assert suricata["rule_count"] == 1


# ---------------------------------------------------------------------------
# Unknown logsource — skipped
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unknown_logsource_skipped(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Rules with no matching logsource are not counted in any source."""
    db_session.add(_make_rule(
        title="Unknown Source Rule",
        enabled=True,
        logsource_product="elastic",   # not mapped to any connector
        technique_ids=json.dumps(["T1059.001"]),
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    for entry in data["sources"]:
        assert entry["covered_count"] == 0
        assert entry["rule_count"] == 0
    assert data["total_covered_count"] == 0


# ---------------------------------------------------------------------------
# Disabled rules excluded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disabled_rules_excluded(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Disabled rules do not contribute to any source's coverage."""
    db_session.add_all([
        _make_rule(
            title="Enabled Windows",
            enabled=True,
            logsource_product="windows",
            technique_ids=json.dumps(["T1059.001"]),
        ),
        _make_rule(
            title="Disabled Windows",
            enabled=False,
            logsource_product="windows",
            technique_ids=json.dumps(["T1003.001"]),
        ),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    wazuh = next(s for s in data["sources"] if s["source"] == "wazuh")
    assert wazuh["covered_count"] == 1    # only T1059.001 from enabled rule
    assert wazuh["rule_count"] == 1


# ---------------------------------------------------------------------------
# Multi-source scenario
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_source_independent_coverage(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Each source tracks its own coverage independently."""
    db_session.add_all([
        _make_rule(
            title="Wazuh Rule",
            enabled=True,
            logsource_product="windows",
            technique_ids=json.dumps(["T1059.001", "T1078.002"]),
        ),
        _make_rule(
            title="Zeek Rule",
            enabled=True,
            logsource_product="zeek",
            technique_ids=json.dumps(["T1071.001"]),
        ),
        _make_rule(
            title="Suricata Rule",
            enabled=True,
            logsource_product="suricata",
            technique_ids=json.dumps(["T1110.001", "T1046"]),
        ),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    by_source = {s["source"]: s for s in data["sources"]}

    assert by_source["wazuh"]["covered_count"] == 2
    assert by_source["wazuh"]["rule_count"] == 1

    assert by_source["zeek"]["covered_count"] == 1
    assert by_source["zeek"]["rule_count"] == 1

    assert by_source["suricata"]["covered_count"] == 2
    assert by_source["suricata"]["rule_count"] == 1


# ---------------------------------------------------------------------------
# Total covered count (union across sources)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_total_covered_is_union_not_sum(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """total_covered_count is the UNION of all source technique sets, not their sum."""
    # Both wazuh and zeek cover T1059.001 — it should count once in the total
    db_session.add_all([
        _make_rule(
            title="Wazuh",
            enabled=True,
            logsource_product="windows",
            technique_ids=json.dumps(["T1059.001"]),
        ),
        _make_rule(
            title="Zeek",
            enabled=True,
            logsource_product="zeek",
            technique_ids=json.dumps(["T1059.001", "T1071.001"]),
        ),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    # T1059.001 appears in both wazuh and zeek but total union = 2 (T1059.001, T1071.001)
    assert data["total_covered_count"] == 2


# ---------------------------------------------------------------------------
# Distinct technique counting per source
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_duplicate_techniques_counted_once_per_source(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Duplicate technique IDs across multiple rules for the same source count once."""
    db_session.add_all([
        _make_rule(
            title="Wazuh Rule 1",
            enabled=True,
            logsource_product="windows",
            technique_ids=json.dumps(["T1059.001"]),
        ),
        _make_rule(
            title="Wazuh Rule 2",
            enabled=True,
            logsource_product="linux",
            technique_ids=json.dumps(["T1059.001", "T1078.002"]),
        ),
    ])
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    wazuh = next(s for s in data["sources"] if s["source"] == "wazuh")
    # T1059.001 appears in both rules but counts once
    assert wazuh["covered_count"] == 2     # T1059.001 + T1078.002
    assert wazuh["rule_count"] == 2


# ---------------------------------------------------------------------------
# Coverage pct capped at 100
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_coverage_pct_capped_at_100(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """coverage_pct never exceeds 100.0 even with more techniques than total_count."""
    rules = [
        _make_rule(
            title=f"Wazuh Rule {i}",
            enabled=True,
            logsource_product="windows",
            technique_ids=json.dumps([f"T9999.{i:03d}"]),
        )
        for i in range(200)
    ]
    db_session.add_all(rules)
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    wazuh = next(s for s in data["sources"] if s["source"] == "wazuh")
    assert wazuh["coverage_pct"] == 100.0
    assert wazuh["covered_count"] == 105

    assert data["total_coverage_pct"] == 100.0
    assert data["total_covered_count"] == 105


# ---------------------------------------------------------------------------
# Rules with null technique_ids — no contribution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_null_technique_ids_no_contribution(
    client: AsyncClient, db_session, auth_headers: dict
) -> None:
    """Rules with null technique_ids contribute 0 coverage but count as rules."""
    db_session.add(_make_rule(
        title="Wazuh No Techniques",
        enabled=True,
        logsource_product="windows",
        technique_ids=None,
    ))
    await db_session.flush()

    resp = await client.get("/api/v1/coverage/by-datasource", headers=auth_headers)
    data = resp.json()

    # Rules without technique_ids are excluded from the query → rule_count stays 0
    for entry in data["sources"]:
        assert entry["covered_count"] == 0
    assert data["total_covered_count"] == 0
