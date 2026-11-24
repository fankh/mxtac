"""Rules with invalid or unsupported Sigma syntax are rejected with a reason at
create, update, import and test time — never stored to silently never match."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

BASE_URL = "/api/v1/rules"

VALID_RULE = """\
title: Valid rule
id: 3f0b6c1d-2a4e-4b7f-9d8c-5e6a7b8c9d07
logsource:
  product: linux
detection:
  sel_a:
    message|contains: 'alpha'
  sel_b:
    message|contains: 'beta'
  filter:
    app_name: 'cron'
  condition: (sel_a or sel_b) and not filter
tags:
  - attack.credential-access
  - attack.t1110
"""


def _rule(condition: str = "selection", selection: str = "message|contains: 'x'", extra: str = "") -> str:
    return (
        "title: Unsupported rule\n"
        "logsource:\n  product: linux\n"
        f"detection:\n  selection:\n    {selection}\n{extra}  condition: {condition}\n"
    )


UNSUPPORTED = [
    pytest.param(_rule(condition="selection | count() by src_ip > 10"), "aggregation", id="aggregation"),
    pytest.param(_rule(extra="  timeframe: 5m\n"), "timeframe", id="timeframe"),
    pytest.param(_rule(selection="CommandLine|windash|contains: '-enc'"), "unsupported modifier 'windash'", id="modifier"),
    pytest.param(_rule(condition="selection and missing"), "unknown selection 'missing'", id="unknown-selection"),
    pytest.param(_rule(condition="(selection"), "missing ')'", id="unbalanced"),
    pytest.param(_rule(selection="message|re: '[unclosed'"), "invalid regular expression", id="regex"),
    pytest.param(_rule(selection="src_ip|cidr: 'not-a-network'"), "invalid CIDR network", id="cidr"),
    pytest.param("title: Correlation\ncorrelation:\n  type: event_count\n", "correlation rules are not supported", id="correlation"),
]


@pytest.mark.parametrize(("content", "reason"), UNSUPPORTED)
async def test_create_rejects_with_reason(
    client: AsyncClient, engineer_headers: dict, content: str, reason: str
) -> None:
    resp = await client.post(
        BASE_URL, json={"title": "x", "content": content}, headers=engineer_headers
    )

    assert resp.status_code == 422
    assert reason in resp.json()["detail"]
    assert (await client.get(BASE_URL, headers=engineer_headers)).json() == []


@pytest.mark.parametrize(("content", "reason"), UNSUPPORTED)
async def test_test_endpoint_reports_reason(
    client: AsyncClient, engineer_headers: dict, content: str, reason: str
) -> None:
    resp = await client.post(
        f"{BASE_URL}/test",
        json={"content": content, "sample_event": {"message": "x"}},
        headers=engineer_headers,
    )

    body = resp.json()
    assert resp.status_code == 200
    assert body["matched"] is False
    assert any(reason in error for error in body["errors"]) or "detection" in body["errors"][0]


async def test_import_skips_unsupported_rules_and_reports_them(
    client: AsyncClient, engineer_headers: dict
) -> None:
    bundle = "\n---\n".join([VALID_RULE, _rule(condition="selection | count() > 5")])

    resp = await client.post(
        f"{BASE_URL}/import", json={"yaml_content": bundle}, headers=engineer_headers
    )

    body = resp.json()
    assert resp.status_code == 200
    assert body["imported"] == 1
    assert body["total_rules"] == 1
    assert len(body["errors"]) == 1
    assert "Unsupported rule" in body["errors"][0]
    assert "aggregation" in body["errors"][0]


async def test_update_rejects_unsupported_content_and_keeps_stored_rule(
    client: AsyncClient, engineer_headers: dict
) -> None:
    created = await client.post(
        BASE_URL, json={"title": "Valid rule", "content": VALID_RULE}, headers=engineer_headers
    )
    assert created.status_code == 201
    rule_id = created.json()["id"]

    resp = await client.patch(
        f"{BASE_URL}/{rule_id}",
        json={"content": _rule(extra="  timeframe: 5m\n")},
        headers=engineer_headers,
    )

    assert resp.status_code == 422
    assert "timeframe" in resp.json()["detail"]
    stored = await client.get(f"{BASE_URL}/{rule_id}", headers=engineer_headers)
    assert "sel_a or sel_b" in stored.json()["content"]


async def test_valid_rule_with_nested_condition_and_named_tactic_is_accepted(
    client: AsyncClient, engineer_headers: dict
) -> None:
    created = await client.post(
        BASE_URL, json={"title": "Valid rule", "content": VALID_RULE}, headers=engineer_headers
    )

    assert created.status_code == 201
    assert created.json()["tactic_ids"] == ["TA0006"]
    assert created.json()["technique_ids"] == ["T1110"]

    async def _matches(sample_event: dict) -> bool:
        resp = await client.post(
            f"{BASE_URL}/{created.json()['id']}/test",
            json={"sample_event": sample_event},
            headers=engineer_headers,
        )
        assert resp.json()["errors"] == []
        return resp.json()["matched"]

    assert await _matches({"message": "BETA build", "app_name": "sshd"}) is True
    assert await _matches({"message": "beta build", "app_name": "cron"}) is False
    assert await _matches({"message": "gamma", "app_name": "sshd"}) is False
