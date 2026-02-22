"""Tests for /api/v1/notifications/channels endpoints.

Coverage:
  - Auth: unauthenticated → 401/403; analyst → 403 (engineer+ required)
  - GET /notifications/channels: empty DB → []; after create → channel in list
  - GET /notifications/channels/{id}: 200 with correct fields; 404 when not found
  - POST /notifications/channels: 422 on invalid channel_type; 422 on invalid min_severity
  - POST /notifications/channels: 422 when required config keys missing per channel type
  - POST /notifications/channels: 201 on valid payload for all 4 channel types
  - PATCH /notifications/channels/{id}: enable/disable; update min_severity; update config; 404
  - DELETE /notifications/channels/{id}: 204 on success; 404 when not found; gone from list
  - POST /notifications/channels/{id}/test: 404 when not found; 200 with sent/message fields

Uses in-memory SQLite via the ``client`` fixture (get_db overridden).
``NotificationChannelRepo`` performs real SQL — no DB mocks needed.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient

BASE_URL = "/api/v1/notifications/channels"

_VALID_EMAIL_PAYLOAD = {
    "name": "email-ops",
    "channel_type": "email",
    "config": {"to_addresses": ["ops@example.com"]},
    "enabled": True,
    "min_severity": "medium",
}

_VALID_SLACK_PAYLOAD = {
    "name": "slack-alerts",
    "channel_type": "slack",
    "config": {"webhook_url": "https://hooks.slack.com/test"},
    "enabled": True,
    "min_severity": "high",
}

_VALID_WEBHOOK_PAYLOAD = {
    "name": "webhook-siem",
    "channel_type": "webhook",
    "config": {"url": "https://siem.example.com/ingest"},
    "enabled": True,
    "min_severity": "low",
}

_VALID_MSTEAMS_PAYLOAD = {
    "name": "teams-soc",
    "channel_type": "msteams",
    "config": {"webhook_url": "https://outlook.office.com/webhook/test"},
    "enabled": True,
    "min_severity": "critical",
}


# ---------------------------------------------------------------------------
# Auth / access control
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_channels_unauthenticated(client: AsyncClient) -> None:
    """GET /notifications/channels without auth → 401 or 403."""
    resp = await client.get(BASE_URL)
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_list_channels_analyst_denied(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """GET /notifications/channels with analyst role → 403 (engineer+ required)."""
    resp = await client.get(BASE_URL, headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_channel_analyst_denied(
    client: AsyncClient, analyst_headers: dict
) -> None:
    """POST /notifications/channels with analyst role → 403."""
    resp = await client.post(
        BASE_URL, headers=analyst_headers, json=_VALID_EMAIL_PAYLOAD
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_delete_channel_analyst_denied(
    client: AsyncClient, engineer_headers: dict, analyst_headers: dict
) -> None:
    """DELETE /notifications/channels/{id} with analyst role → 403."""
    create_resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD
    )
    ch_id = create_resp.json()["id"]
    resp = await client.delete(f"{BASE_URL}/{ch_id}", headers=analyst_headers)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# List channels
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_channels_empty(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """GET /notifications/channels with empty DB → []."""
    resp = await client.get(BASE_URL, headers=engineer_headers)
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_channels_after_create(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """After creating a channel, it appears in GET /notifications/channels."""
    await client.post(BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD)
    resp = await client.get(BASE_URL, headers=engineer_headers)
    assert resp.status_code == 200
    names = [ch["name"] for ch in resp.json()]
    assert _VALID_EMAIL_PAYLOAD["name"] in names


# ---------------------------------------------------------------------------
# GET single channel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_channel_not_found(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """GET /notifications/channels/{id} for unknown ID → 404."""
    resp = await client.get(f"{BASE_URL}/99999", headers=engineer_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Notification channel not found"


@pytest.mark.asyncio
async def test_get_channel_success(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """GET /notifications/channels/{id} for existing channel → 200 with correct fields."""
    create_resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD
    )
    ch_id = create_resp.json()["id"]
    resp = await client.get(f"{BASE_URL}/{ch_id}", headers=engineer_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == ch_id
    assert data["name"] == _VALID_EMAIL_PAYLOAD["name"]
    assert data["channel_type"] == "email"
    assert data["enabled"] is True
    assert data["min_severity"] == "medium"
    assert "created_at" in data
    assert "updated_at" in data


# ---------------------------------------------------------------------------
# POST create channel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_channel_invalid_type(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels with unknown channel_type → 422."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"name": "bad-channel", "channel_type": "pigeon", "config": {}},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_channel_invalid_severity(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels with invalid min_severity → 422."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={
            "name": "bad-sev",
            "channel_type": "slack",
            "config": {"webhook_url": "https://hooks.slack.com/x"},
            "min_severity": "extreme",
        },
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_channel_email_missing_to_addresses(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels email without to_addresses → 422."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"name": "email-bad", "channel_type": "email", "config": {}},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_channel_slack_missing_webhook_url(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels slack without webhook_url → 422."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"name": "slack-bad", "channel_type": "slack", "config": {}},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_channel_webhook_missing_url(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels webhook without url → 422."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"name": "wh-bad", "channel_type": "webhook", "config": {}},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_channel_msteams_missing_webhook_url(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels msteams without webhook_url → 422."""
    resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={"name": "teams-bad", "channel_type": "msteams", "config": {}},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_channel_email_success(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels email with valid payload → 201."""
    resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == _VALID_EMAIL_PAYLOAD["name"]
    assert data["channel_type"] == "email"
    assert data["enabled"] is True
    assert data["min_severity"] == "medium"
    assert "id" in data
    assert data["config"]["to_addresses"] == ["ops@example.com"]


@pytest.mark.asyncio
async def test_create_channel_slack_success(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels slack with valid payload → 201."""
    resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_SLACK_PAYLOAD
    )
    assert resp.status_code == 201
    assert resp.json()["channel_type"] == "slack"


@pytest.mark.asyncio
async def test_create_channel_webhook_success(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels webhook with valid payload → 201."""
    resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_WEBHOOK_PAYLOAD
    )
    assert resp.status_code == 201
    assert resp.json()["channel_type"] == "webhook"


@pytest.mark.asyncio
async def test_create_channel_msteams_success(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels msteams with valid payload → 201."""
    resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_MSTEAMS_PAYLOAD
    )
    assert resp.status_code == 201
    assert resp.json()["channel_type"] == "msteams"


@pytest.mark.asyncio
async def test_create_channel_disabled(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels with enabled=False → 201 with enabled=False."""
    payload = {**_VALID_SLACK_PAYLOAD, "name": "slack-disabled", "enabled": False}
    resp = await client.post(BASE_URL, headers=engineer_headers, json=payload)
    assert resp.status_code == 201
    assert resp.json()["enabled"] is False


# ---------------------------------------------------------------------------
# PATCH update channel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_channel_not_found(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /notifications/channels/{id} for unknown ID → 404."""
    resp = await client.patch(
        f"{BASE_URL}/99999", headers=engineer_headers, json={"enabled": False}
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Notification channel not found"


@pytest.mark.asyncio
async def test_update_channel_disable(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /notifications/channels/{id} with enabled=False disables the channel."""
    create_resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD
    )
    ch_id = create_resp.json()["id"]
    resp = await client.patch(
        f"{BASE_URL}/{ch_id}", headers=engineer_headers, json={"enabled": False}
    )
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


@pytest.mark.asyncio
async def test_update_channel_min_severity(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /notifications/channels/{id} updates min_severity."""
    create_resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD
    )
    ch_id = create_resp.json()["id"]
    resp = await client.patch(
        f"{BASE_URL}/{ch_id}", headers=engineer_headers, json={"min_severity": "critical"}
    )
    assert resp.status_code == 200
    assert resp.json()["min_severity"] == "critical"


@pytest.mark.asyncio
async def test_update_channel_invalid_severity(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /notifications/channels/{id} with invalid min_severity → 422."""
    create_resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD
    )
    ch_id = create_resp.json()["id"]
    resp = await client.patch(
        f"{BASE_URL}/{ch_id}", headers=engineer_headers, json={"min_severity": "extreme"}
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_update_channel_config(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH /notifications/channels/{id} replaces config."""
    create_resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD
    )
    ch_id = create_resp.json()["id"]
    new_config = {"to_addresses": ["new@example.com"], "smtp_host": "smtp.example.com"}
    resp = await client.patch(
        f"{BASE_URL}/{ch_id}", headers=engineer_headers, json={"config": new_config}
    )
    assert resp.status_code == 200
    assert resp.json()["config"]["smtp_host"] == "smtp.example.com"


# ---------------------------------------------------------------------------
# DELETE channel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_channel_not_found(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """DELETE /notifications/channels/{id} for unknown ID → 404."""
    resp = await client.delete(f"{BASE_URL}/99999", headers=engineer_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Notification channel not found"


@pytest.mark.asyncio
async def test_delete_channel_success(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """DELETE /notifications/channels/{id} for an existing channel → 204."""
    create_resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD
    )
    ch_id = create_resp.json()["id"]
    resp = await client.delete(f"{BASE_URL}/{ch_id}", headers=engineer_headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_deleted_channel_absent_from_list(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """After DELETE, the channel no longer appears in GET /notifications/channels."""
    create_resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD
    )
    ch_id = create_resp.json()["id"]
    await client.delete(f"{BASE_URL}/{ch_id}", headers=engineer_headers)
    list_resp = await client.get(BASE_URL, headers=engineer_headers)
    ids = [ch["id"] for ch in list_resp.json()]
    assert ch_id not in ids


# ---------------------------------------------------------------------------
# POST /{id}/test — send test notification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_channel_test_not_found(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels/{id}/test for unknown ID → 404."""
    resp = await client.post(f"{BASE_URL}/99999/test", headers=engineer_headers)
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Notification channel not found"


@pytest.mark.asyncio
async def test_channel_test_success(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels/{id}/test → 200 with sent=True (dispatcher mocked)."""
    create_resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD
    )
    ch_id = create_resp.json()["id"]

    _PATCH = "app.api.v1.endpoints.notifications.NotificationDispatcher"
    with patch(_PATCH) as MockDispatcher:
        mock_inst = MagicMock()
        mock_inst._dispatch_one = AsyncMock(return_value=None)
        mock_inst.close = AsyncMock(return_value=None)
        MockDispatcher.return_value = mock_inst

        resp = await client.post(f"{BASE_URL}/{ch_id}/test", headers=engineer_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["channel_id"] == ch_id
    assert data["sent"] is True
    assert "message" in data
    mock_inst._dispatch_one.assert_called_once()


@pytest.mark.asyncio
async def test_channel_test_failure_returns_sent_false(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST /notifications/channels/{id}/test → 200 with sent=False when dispatch raises."""
    create_resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_EMAIL_PAYLOAD
    )
    ch_id = create_resp.json()["id"]

    _PATCH = "app.api.v1.endpoints.notifications.NotificationDispatcher"
    with patch(_PATCH) as MockDispatcher:
        mock_inst = MagicMock()
        mock_inst._dispatch_one = AsyncMock(
            side_effect=ConnectionError("SMTP connection refused")
        )
        mock_inst.close = AsyncMock(return_value=None)
        MockDispatcher.return_value = mock_inst

        resp = await client.post(f"{BASE_URL}/{ch_id}/test", headers=engineer_headers)

    assert resp.status_code == 200
    data = resp.json()
    assert data["channel_id"] == ch_id
    assert data["sent"] is False
    assert "SMTP connection refused" in data["message"]


# ---------------------------------------------------------------------------
# routing_rules — create / update / read
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_channel_with_routing_rules(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST with routing_rules → 201 and rules persisted in response."""
    payload = {
        **_VALID_SLACK_PAYLOAD,
        "name": "slack-lateral-only",
        "routing_rules": [
            {"field": "tactic", "operator": "eq", "value": "lateral-movement"}
        ],
    }
    resp = await client.post(BASE_URL, headers=engineer_headers, json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["routing_rules"] == [
        {"field": "tactic", "operator": "eq", "value": "lateral-movement"}
    ]


@pytest.mark.asyncio
async def test_create_channel_invalid_routing_rule_field(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST with invalid routing rule field → 422."""
    payload = {
        **_VALID_SLACK_PAYLOAD,
        "name": "slack-bad-field",
        "routing_rules": [{"field": "not_a_field", "operator": "eq", "value": "x"}],
    }
    resp = await client.post(BASE_URL, headers=engineer_headers, json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_channel_invalid_routing_rule_operator(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST with invalid routing rule operator → 422."""
    payload = {
        **_VALID_SLACK_PAYLOAD,
        "name": "slack-bad-op",
        "routing_rules": [{"field": "severity", "operator": "startswith", "value": "hi"}],
    }
    resp = await client.post(BASE_URL, headers=engineer_headers, json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_channel_in_operator_requires_list(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST with 'in' operator and non-list value → 422."""
    payload = {
        **_VALID_SLACK_PAYLOAD,
        "name": "slack-in-bad",
        "routing_rules": [{"field": "severity", "operator": "in", "value": "high"}],
    }
    resp = await client.post(BASE_URL, headers=engineer_headers, json=payload)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_channel_empty_routing_rules(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """POST with empty routing_rules → 201 and empty list in response."""
    payload = {**_VALID_SLACK_PAYLOAD, "name": "slack-no-rules", "routing_rules": []}
    resp = await client.post(BASE_URL, headers=engineer_headers, json=payload)
    assert resp.status_code == 201
    assert resp.json()["routing_rules"] == []


@pytest.mark.asyncio
async def test_update_channel_routing_rules(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """PATCH routing_rules → rules updated in response."""
    create_resp = await client.post(
        BASE_URL, headers=engineer_headers, json=_VALID_SLACK_PAYLOAD
    )
    ch_id = create_resp.json()["id"]

    patch_resp = await client.patch(
        f"{BASE_URL}/{ch_id}",
        headers=engineer_headers,
        json={
            "routing_rules": [
                {"field": "severity", "operator": "in", "value": ["high", "critical"]}
            ]
        },
    )
    assert patch_resp.status_code == 200
    data = patch_resp.json()
    assert data["routing_rules"] == [
        {"field": "severity", "operator": "in", "value": ["high", "critical"]}
    ]


@pytest.mark.asyncio
async def test_get_channel_includes_routing_rules(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """GET /{id} response includes routing_rules field."""
    payload = {
        **_VALID_WEBHOOK_PAYLOAD,
        "name": "webhook-with-rules",
        "routing_rules": [{"field": "host", "operator": "contains", "value": "prod"}],
    }
    create_resp = await client.post(BASE_URL, headers=engineer_headers, json=payload)
    ch_id = create_resp.json()["id"]

    resp = await client.get(f"{BASE_URL}/{ch_id}", headers=engineer_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "routing_rules" in data
    assert data["routing_rules"] == [
        {"field": "host", "operator": "contains", "value": "prod"}
    ]


# ---------------------------------------------------------------------------
# GET /{id}/test-rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_test_rule_not_found(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """GET /test-rule for non-existent channel → 404."""
    resp = await client.get(f"{BASE_URL}/999/test-rule", headers=engineer_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_test_rule_empty_rules_always_matched(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """GET /test-rule with empty routing_rules → matched=True."""
    create_resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={**_VALID_SLACK_PAYLOAD, "name": "slack-test-rule-empty"},
    )
    ch_id = create_resp.json()["id"]

    resp = await client.get(f"{BASE_URL}/{ch_id}/test-rule", headers=engineer_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["matched"] is True
    assert data["channel_id"] == ch_id
    assert "routing_rules" in data
    assert "sample_alert" in data


@pytest.mark.asyncio
async def test_test_rule_matches_when_rule_satisfied(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """GET /test-rule → matched=True when the tactic query param satisfies the rule."""
    payload = {
        **_VALID_SLACK_PAYLOAD,
        "name": "slack-tactic-rule",
        "routing_rules": [
            {"field": "tactic", "operator": "eq", "value": "lateral-movement"}
        ],
    }
    create_resp = await client.post(BASE_URL, headers=engineer_headers, json=payload)
    ch_id = create_resp.json()["id"]

    resp = await client.get(
        f"{BASE_URL}/{ch_id}/test-rule",
        headers=engineer_headers,
        params={"tactic": "lateral-movement"},
    )
    assert resp.status_code == 200
    assert resp.json()["matched"] is True


@pytest.mark.asyncio
async def test_test_rule_no_match_when_rule_not_satisfied(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """GET /test-rule → matched=False when the sample alert doesn't satisfy the rule."""
    payload = {
        **_VALID_SLACK_PAYLOAD,
        "name": "slack-tactic-rule-2",
        "routing_rules": [
            {"field": "tactic", "operator": "eq", "value": "lateral-movement"}
        ],
    }
    create_resp = await client.post(BASE_URL, headers=engineer_headers, json=payload)
    ch_id = create_resp.json()["id"]

    resp = await client.get(
        f"{BASE_URL}/{ch_id}/test-rule",
        headers=engineer_headers,
        params={"tactic": "discovery"},  # does NOT match lateral-movement
    )
    assert resp.status_code == 200
    assert resp.json()["matched"] is False


@pytest.mark.asyncio
async def test_test_rule_query_params_build_sample_alert(
    client: AsyncClient, engineer_headers: dict
) -> None:
    """GET /test-rule query params are reflected in sample_alert."""
    create_resp = await client.post(
        BASE_URL,
        headers=engineer_headers,
        json={**_VALID_SLACK_PAYLOAD, "name": "slack-param-test"},
    )
    ch_id = create_resp.json()["id"]

    resp = await client.get(
        f"{BASE_URL}/{ch_id}/test-rule",
        headers=engineer_headers,
        params={
            "severity": "critical",
            "tactic": "impact",
            "technique_id": "T1486",
            "host": "prod-db-01",
            "rule_name": "Ransomware Detected",
        },
    )
    assert resp.status_code == 200
    sample = resp.json()["sample_alert"]
    assert sample["level"] == "critical"
    assert sample["tactic_ids"] == ["impact"]
    assert sample["technique_ids"] == ["T1486"]
    assert sample["host"] == "prod-db-01"
    assert sample["rule_title"] == "Ransomware Detected"


@pytest.mark.asyncio
async def test_test_rule_requires_auth(client: AsyncClient) -> None:
    """GET /test-rule without auth → 401 or 403."""
    resp = await client.get(f"{BASE_URL}/1/test-rule")
    assert resp.status_code in (401, 403)
