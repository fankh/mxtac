"""Rule changes take effect in the running engine.

Found while driving the real UI against the real backend:

  - A rule created in the UI did not detect anything, and a disabled or deleted
    rule kept detecting.  The reload signal was published before the request
    had committed, so this replica reloaded its engine from the database
    without the change and dropped the update the request had just made.
  - Creating a rule whose ``id`` exists answered 500.
  - The stored YAML had its keys sorted, so the editor showed another text
    than the one that was saved.
"""

from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import patch

import pytest

from app.api.v1.endpoints import rules as rules_endpoint

RULES = "/api/v1/rules"
RULE_ID = "6f1c2a58-93d4-4c1e-8a57-2b7d0e4c9a31"
RULE_YAML = f"""title: Crontab Edited From the Command Line
id: {RULE_ID}
status: experimental
level: low
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: 'crontab -e'
  condition: selection
tags:
  - attack.t1053.003
"""
OTHER_YAML = RULE_YAML.replace(RULE_ID, "3d5b2f6e-7a41-4b8e-9c52-1e0f4a7b6d90").replace("Crontab Edited", "Crontab Removed")


@pytest.fixture
def order(db_session) -> Iterator[list[str]]:
    """Records commits of the request session and reload signals, in order."""
    calls: list[str] = []
    real_commit = db_session.commit

    async def _commit() -> None:
        calls.append("commit")
        await real_commit()

    async def _publish() -> None:
        calls.append("publish")

    with (
        patch.object(db_session, "commit", _commit),
        patch.object(rules_endpoint, "publish_rule_reload", _publish),
    ):
        yield calls


def _create(client, headers, content: str = RULE_YAML):
    return client.post(RULES, json={"title": "t", "content": content, "enabled": True}, headers=headers)


async def test_create_commits_before_the_reload_signal(client, engineer_headers, order) -> None:
    resp = await _create(client, engineer_headers)
    assert resp.status_code == 201
    assert resp.json()["id"] == RULE_ID
    assert order == ["commit", "publish"]


async def test_update_commits_before_the_reload_signal(client, engineer_headers, order) -> None:
    await _create(client, engineer_headers)
    order.clear()

    resp = await client.patch(f"{RULES}/{RULE_ID}", json={"enabled": False}, headers=engineer_headers)

    assert resp.status_code == 200
    assert resp.json()["enabled"] is False
    assert order == ["commit", "publish"]


async def test_delete_commits_before_the_reload_signal(client, engineer_headers, order) -> None:
    await _create(client, engineer_headers)
    order.clear()

    resp = await client.delete(f"{RULES}/{RULE_ID}", headers=engineer_headers)

    assert resp.status_code == 204
    assert order == ["commit", "publish"]


async def test_import_commits_before_the_reload_signal(client, engineer_headers, order) -> None:
    resp = await client.post(f"{RULES}/import", json={"yaml_content": RULE_YAML}, headers=engineer_headers)
    assert resp.json()["imported"] == 1
    assert order == ["commit", "publish"]


async def test_rejected_rule_sends_no_reload_signal(client, engineer_headers, order) -> None:
    resp = await _create(client, engineer_headers, RULE_YAML.replace("condition: selection", "condition: selection | count() > 5"))
    assert resp.status_code == 422
    assert order == []


async def test_duplicate_rule_id_is_refused_with_a_reason(client, engineer_headers, order) -> None:
    assert (await _create(client, engineer_headers)).status_code == 201

    resp = await _create(client, engineer_headers)

    assert resp.status_code == 422
    assert f"a rule with the ID {RULE_ID} already exists" in resp.json()["detail"]


async def test_import_reports_a_duplicate_and_imports_the_rest(client, engineer_headers, order) -> None:
    await _create(client, engineer_headers)

    resp = await client.post(
        f"{RULES}/import", json={"yaml_content": f"{RULE_YAML}---\n{OTHER_YAML}"}, headers=engineer_headers
    )

    body = resp.json()
    assert body["imported"] == 1
    assert len(body["errors"]) == 1
    assert body["errors"][0].startswith("Crontab Edited From the Command Line: a rule with the ID")


async def test_stored_yaml_keeps_the_key_order_of_the_author(client, engineer_headers, order) -> None:
    await _create(client, engineer_headers)

    detail = await client.get(f"{RULES}/{RULE_ID}", headers=engineer_headers)

    keys = [line.split(":")[0] for line in detail.json()["content"].splitlines() if line and not line.startswith((" ", "-"))]
    assert keys == ["title", "id", "status", "level", "logsource", "detection", "tags"]
