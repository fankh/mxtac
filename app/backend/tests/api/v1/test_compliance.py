"""Tests for Feature 31.6 — Compliance framework coverage API.

Verifies:
  - GET /compliance/nist returns 200 with framework, controls, summary
  - GET /compliance/pci-dss returns 200 with framework, controls, summary
  - GET /compliance/{unknown} returns 400
  - controls list has required fields: id, name, covered, techniques, covered_techniques
  - summary has required fields: total_controls, covered_controls, coverage_pct
  - with enabled rule: covered_controls > 0
  - RBAC: viewer denied (403); analyst+ can access
  - Unauthenticated returns 401
"""

from __future__ import annotations

import json

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import new_uuid
from app.models.rule import Rule

_BASE_URL = "/api/v1/compliance"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_rule(
    *,
    enabled: bool = True,
    technique_ids: list[str] | None = None,
) -> Rule:
    return Rule(
        id=new_uuid(),
        title="Test Compliance Rule",
        content="detection:\n  condition: all of them",
        status="stable",
        level="high",
        enabled=enabled,
        rule_type="sigma",
        technique_ids=json.dumps(technique_ids or []),
        tactic_ids=json.dumps(["TA0001"]),
        logsource_product="windows",
        logsource_category="process_creation",
        logsource_service="",
        created_by="analyst",
    )


# ---------------------------------------------------------------------------
# GET /compliance/nist
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nist_returns_200(client: AsyncClient, analyst_headers: dict) -> None:
    """GET /compliance/nist returns 200."""
    resp = await client.get(f"{_BASE_URL}/nist", headers=analyst_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_nist_response_has_framework_key(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/nist", headers=analyst_headers)
    data = resp.json()
    assert data["framework"] == "nist"


@pytest.mark.asyncio
async def test_nist_response_has_controls_list(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/nist", headers=analyst_headers)
    data = resp.json()
    assert "controls" in data
    assert isinstance(data["controls"], list)
    assert len(data["controls"]) > 0


@pytest.mark.asyncio
async def test_nist_controls_have_required_fields(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/nist", headers=analyst_headers)
    data = resp.json()

    for control in data["controls"]:
        assert "id" in control, f"Missing 'id' in {control}"
        assert "name" in control, f"Missing 'name' in {control}"
        assert "covered" in control, f"Missing 'covered' in {control}"
        assert "techniques" in control, f"Missing 'techniques' in {control}"
        assert "covered_techniques" in control, f"Missing 'covered_techniques' in {control}"


@pytest.mark.asyncio
async def test_nist_summary_has_required_fields(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/nist", headers=analyst_headers)
    data = resp.json()
    summary = data["summary"]

    assert "total_controls" in summary
    assert "covered_controls" in summary
    assert "coverage_pct" in summary


@pytest.mark.asyncio
async def test_nist_empty_db_coverage_pct_zero(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """With no rules, coverage is 0%."""
    resp = await client.get(f"{_BASE_URL}/nist", headers=analyst_headers)
    data = resp.json()

    assert data["summary"]["covered_controls"] == 0
    assert data["summary"]["coverage_pct"] == 0.0


@pytest.mark.asyncio
async def test_nist_with_rule_coverage_nonzero(
    client: AsyncClient,
    db_session: AsyncSession,
    analyst_headers: dict,
) -> None:
    """An enabled rule with T1078 covers AC-2, IA-2, IA-5."""
    db_session.add(_make_rule(technique_ids=["T1078"]))
    await db_session.commit()

    resp = await client.get(f"{_BASE_URL}/nist", headers=analyst_headers)
    data = resp.json()

    assert data["summary"]["covered_controls"] > 0
    assert data["summary"]["coverage_pct"] > 0.0
    covered_ids = {c["id"] for c in data["controls"] if c["covered"]}
    assert "AC-2" in covered_ids


# ---------------------------------------------------------------------------
# GET /compliance/pci-dss
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pci_dss_returns_200(client: AsyncClient, analyst_headers: dict) -> None:
    """GET /compliance/pci-dss returns 200."""
    resp = await client.get(f"{_BASE_URL}/pci-dss", headers=analyst_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_pci_dss_response_has_framework_key(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/pci-dss", headers=analyst_headers)
    data = resp.json()
    assert data["framework"] == "pci-dss"


@pytest.mark.asyncio
async def test_pci_dss_response_has_controls_list(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/pci-dss", headers=analyst_headers)
    data = resp.json()
    assert "controls" in data
    assert isinstance(data["controls"], list)
    assert len(data["controls"]) > 0


@pytest.mark.asyncio
async def test_pci_dss_controls_have_required_fields(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/pci-dss", headers=analyst_headers)
    data = resp.json()

    for control in data["controls"]:
        assert "id" in control
        assert "name" in control
        assert "covered" in control
        assert "techniques" in control
        assert "covered_techniques" in control


@pytest.mark.asyncio
async def test_pci_dss_empty_db_coverage_pct_zero(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/pci-dss", headers=analyst_headers)
    data = resp.json()
    assert data["summary"]["covered_controls"] == 0
    assert data["summary"]["coverage_pct"] == 0.0


@pytest.mark.asyncio
async def test_pci_dss_with_rule_coverage_nonzero(
    client: AsyncClient,
    db_session: AsyncSession,
    analyst_headers: dict,
) -> None:
    """An enabled rule with T1078 covers Req-7.1, Req-8.2."""
    db_session.add(_make_rule(technique_ids=["T1078"]))
    await db_session.commit()

    resp = await client.get(f"{_BASE_URL}/pci-dss", headers=analyst_headers)
    data = resp.json()

    assert data["summary"]["covered_controls"] > 0
    covered_ids = {c["id"] for c in data["controls"] if c["covered"]}
    assert "Req-7.1" in covered_ids
    assert "Req-8.2" in covered_ids


# ---------------------------------------------------------------------------
# Invalid framework — 400
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invalid_framework_returns_400(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/iso27001", headers=analyst_headers)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_invalid_framework_error_message(
    client: AsyncClient, analyst_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/unknown", headers=analyst_headers)
    assert "Invalid framework" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# RBAC — viewer denied
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewer_cannot_get_nist(
    client: AsyncClient, viewer_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/nist", headers=viewer_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_get_pci_dss(
    client: AsyncClient, viewer_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/pci-dss", headers=viewer_headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# RBAC — analyst+ allowed
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hunter_can_get_nist(
    client: AsyncClient, hunter_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/nist", headers=hunter_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_engineer_can_get_pci_dss(
    client: AsyncClient, engineer_headers: dict
) -> None:
    resp = await client.get(f"{_BASE_URL}/pci-dss", headers=engineer_headers)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Unauthenticated — 401
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unauthenticated_nist(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/nist")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_unauthenticated_pci_dss(client: AsyncClient) -> None:
    resp = await client.get(f"{_BASE_URL}/pci-dss")
    assert resp.status_code == 401
