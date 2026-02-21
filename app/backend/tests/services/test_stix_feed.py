"""Tests for STIXFeedIngester and stix_feed_poller — feature 29.5.

Coverage:
  parse_bundle():
  - IPv4 indicator extracted correctly
  - Domain indicator extracted correctly
  - URL indicator extracted correctly
  - MD5 hash indicator extracted correctly
  - SHA-256 hash indicator extracted correctly
  - Email indicator extracted correctly
  - Non-indicator objects (bundle, malware, etc.) are skipped
  - Objects with empty/absent pattern are skipped
  - Objects with unrecognised pattern return no IOCs
  - Confidence 0 → severity=low, source=feed name
  - Confidence 25 → severity=low
  - Confidence 26 → severity=medium
  - Confidence 50 → severity=medium
  - Confidence 51 → severity=high
  - Confidence 75 → severity=high
  - Confidence 76 → severity=critical
  - Confidence 100 → severity=critical
  - Confidence clamped to [0, 100] when out of range
  - valid_until mapped to expires_at
  - Absent valid_until → expires_at is None
  - valid_from mapped to first_seen; falls back to now when absent
  - modified mapped to last_seen; falls back to now when absent
  - labels mapped to tags
  - description truncated at 500 chars
  - is_active always True
  - Empty bundle returns []
  - Multiple indicators in one bundle all returned

  poll():
  - Successful response returns parsed bundle dict
  - HTTP 401 returns None (non-fatal)
  - HTTP 404 returns None (non-fatal)
  - Connection error returns None (non-fatal)
  - First poll: no added_after query parameter
  - Subsequent poll: added_after set from _last_poll
  - _last_poll updated on success
  - _last_poll NOT updated on HTTP error
  - Authorization header present when api_key configured
  - Authorization header absent when api_key is empty
  - Accept header is always application/taxii+json;version=2.1

  ingest():
  - Returns (0, 0) when poll returns None
  - Returns (0, 0) when bundle has no parseable indicators
  - Returns (created, skipped) from IOCRepo.bulk_create
  - Calls IOCRepo.bulk_create with correct dicts
  - Commits the session after bulk_create

  stix_feed_poller():
  - Empty configs exits immediately
  - Calls ingest() for each feed when next_poll time is reached
  - Catches exceptions from ingest() and continues (non-fatal)
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.core.config import ThreatIntelFeedConfig
from app.services.stix_feed import (
    STIXFeedIngester,
    _confidence_to_severity,
    _parse_stix_datetime,
    stix_feed_poller,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(
    *,
    name: str = "test-feed",
    taxii_url: str = "https://taxii.example.com/api",
    collection_id: str = "col-001",
    api_key: str = "secret-key",
    poll_interval: int = 3600,
) -> ThreatIntelFeedConfig:
    return ThreatIntelFeedConfig(
        name=name,
        taxii_url=taxii_url,
        collection_id=collection_id,
        api_key=api_key,
        poll_interval=poll_interval,
    )


def _make_indicator(
    *,
    pattern: str = "[ipv4-addr:value = '1.2.3.4']",
    confidence: int = 75,
    valid_from: str = "2024-01-01T00:00:00Z",
    modified: str = "2024-06-01T00:00:00Z",
    valid_until: str | None = "2025-01-01T00:00:00Z",
    labels: list[str] | None = None,
    description: str | None = "Test indicator",
    name_field: str | None = None,
) -> dict:
    obj: dict = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--test-001",
        "created": valid_from,
        "modified": modified,
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": valid_from,
        "confidence": confidence,
        "labels": labels or [],
    }
    if valid_until is not None:
        obj["valid_until"] = valid_until
    if description is not None:
        obj["description"] = description
    if name_field is not None:
        obj["name"] = name_field
    return obj


def _make_bundle(*objects) -> dict:
    return {
        "type": "bundle",
        "id": "bundle--test",
        "spec_version": "2.1",
        "objects": list(objects),
    }


# ---------------------------------------------------------------------------
# Section 1 — _confidence_to_severity() helper
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "confidence, expected",
    [
        (0, "low"),
        (25, "low"),
        (26, "medium"),
        (50, "medium"),
        (51, "high"),
        (75, "high"),
        (76, "critical"),
        (100, "critical"),
    ],
)
def test_confidence_to_severity(confidence: int, expected: str):
    assert _confidence_to_severity(confidence) == expected


# ---------------------------------------------------------------------------
# Section 2 — _parse_stix_datetime() helper
# ---------------------------------------------------------------------------


def test_parse_stix_datetime_valid_z_suffix():
    result = _parse_stix_datetime("2024-01-15T12:30:00Z")
    assert result is not None
    assert result.tzinfo is not None
    assert result.year == 2024
    assert result.month == 1
    assert result.day == 15


def test_parse_stix_datetime_none_input():
    assert _parse_stix_datetime(None) is None


def test_parse_stix_datetime_empty_string():
    assert _parse_stix_datetime("") is None


def test_parse_stix_datetime_invalid_string():
    assert _parse_stix_datetime("not-a-date") is None


# ---------------------------------------------------------------------------
# Section 3 — parse_bundle(): indicator type extraction
# ---------------------------------------------------------------------------


def test_parse_bundle_ipv4():
    """IPv4 indicator is extracted with ioc_type='ip'."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(pattern="[ipv4-addr:value = '1.2.3.4']"))
    iocs = ingester.parse_bundle(bundle)
    assert len(iocs) == 1
    assert iocs[0]["ioc_type"] == "ip"
    assert iocs[0]["value"] == "1.2.3.4"


def test_parse_bundle_domain():
    """Domain indicator is extracted with ioc_type='domain'."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(pattern="[domain-name:value = 'evil.example.com']"))
    iocs = ingester.parse_bundle(bundle)
    assert len(iocs) == 1
    assert iocs[0]["ioc_type"] == "domain"
    assert iocs[0]["value"] == "evil.example.com"


def test_parse_bundle_url():
    """URL indicator is extracted with ioc_type='url'."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(pattern="[url:value = 'http://evil.com/path']"))
    iocs = ingester.parse_bundle(bundle)
    assert len(iocs) == 1
    assert iocs[0]["ioc_type"] == "url"
    assert iocs[0]["value"] == "http://evil.com/path"


def test_parse_bundle_hash_md5():
    """MD5 hash indicator is extracted with ioc_type='hash_md5'."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(
        _make_indicator(pattern="[file:hashes.MD5 = 'abc123def456abc123def456abc12345']")
    )
    iocs = ingester.parse_bundle(bundle)
    assert len(iocs) == 1
    assert iocs[0]["ioc_type"] == "hash_md5"
    assert iocs[0]["value"] == "abc123def456abc123def456abc12345"


def test_parse_bundle_hash_sha256():
    """SHA-256 hash indicator is extracted with ioc_type='hash_sha256'."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(
        _make_indicator(
            pattern="[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
        )
    )
    iocs = ingester.parse_bundle(bundle)
    assert len(iocs) == 1
    assert iocs[0]["ioc_type"] == "hash_sha256"
    assert iocs[0]["value"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_parse_bundle_email():
    """Email indicator is extracted with ioc_type='email'."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(pattern="[email-addr:value = 'attacker@evil.com']"))
    iocs = ingester.parse_bundle(bundle)
    assert len(iocs) == 1
    assert iocs[0]["ioc_type"] == "email"
    assert iocs[0]["value"] == "attacker@evil.com"


# ---------------------------------------------------------------------------
# Section 4 — parse_bundle(): filtering non-indicator objects
# ---------------------------------------------------------------------------


def test_parse_bundle_skips_non_indicator_objects():
    """Objects that are not type='indicator' must be ignored."""
    ingester = STIXFeedIngester(_make_config())
    malware_obj = {
        "type": "malware",
        "id": "malware--test",
        "name": "TestMalware",
        "spec_version": "2.1",
        "malware_types": ["trojan"],
    }
    bundle = _make_bundle(malware_obj)
    iocs = ingester.parse_bundle(bundle)
    assert iocs == []


def test_parse_bundle_skips_objects_with_empty_pattern():
    """Indicator objects with empty or absent pattern are skipped."""
    ingester = STIXFeedIngester(_make_config())
    obj_empty = _make_indicator(pattern="")
    obj_absent = {k: v for k, v in _make_indicator().items() if k != "pattern"}
    bundle = _make_bundle(obj_empty, obj_absent)
    iocs = ingester.parse_bundle(bundle)
    assert iocs == []


def test_parse_bundle_skips_unrecognised_pattern():
    """Indicators whose pattern matches no supported extractor return no IOCs."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(pattern="[x509-certificate:subject = 'CN=evil']"))
    iocs = ingester.parse_bundle(bundle)
    assert iocs == []


def test_parse_bundle_empty_bundle():
    """An empty bundle returns an empty list."""
    ingester = STIXFeedIngester(_make_config())
    iocs = ingester.parse_bundle({"type": "bundle", "objects": []})
    assert iocs == []


# ---------------------------------------------------------------------------
# Section 5 — parse_bundle(): field mapping
# ---------------------------------------------------------------------------


def test_parse_bundle_source_is_feed_name():
    """source field must be the feed configuration name."""
    ingester = STIXFeedIngester(_make_config(name="my-feed"))
    bundle = _make_bundle(_make_indicator())
    iocs = ingester.parse_bundle(bundle)
    assert iocs[0]["source"] == "my-feed"


def test_parse_bundle_confidence_mapped_correctly():
    """Confidence is passed through (0-100); severity is derived."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(confidence=80))
    iocs = ingester.parse_bundle(bundle)
    assert iocs[0]["confidence"] == 80
    assert iocs[0]["severity"] == "critical"


def test_parse_bundle_confidence_clamped_above_100():
    """Confidence values above 100 are clamped to 100."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(confidence=999))
    iocs = ingester.parse_bundle(bundle)
    assert iocs[0]["confidence"] == 100


def test_parse_bundle_confidence_clamped_below_0():
    """Confidence values below 0 are clamped to 0."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(confidence=-10))
    iocs = ingester.parse_bundle(bundle)
    assert iocs[0]["confidence"] == 0


def test_parse_bundle_valid_until_mapped_to_expires_at():
    """valid_until is mapped to expires_at as a datetime."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(valid_until="2025-12-31T23:59:59Z"))
    iocs = ingester.parse_bundle(bundle)
    assert iocs[0]["expires_at"] is not None
    assert iocs[0]["expires_at"].year == 2025
    assert iocs[0]["expires_at"].month == 12


def test_parse_bundle_absent_valid_until_gives_none_expires_at():
    """When valid_until is absent, expires_at must be None."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(valid_until=None))
    iocs = ingester.parse_bundle(bundle)
    assert iocs[0]["expires_at"] is None


def test_parse_bundle_valid_from_maps_to_first_seen():
    """valid_from is parsed and stored as first_seen."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(valid_from="2023-03-15T10:00:00Z"))
    iocs = ingester.parse_bundle(bundle)
    assert iocs[0]["first_seen"].year == 2023
    assert iocs[0]["first_seen"].month == 3


def test_parse_bundle_modified_maps_to_last_seen():
    """modified timestamp is parsed and stored as last_seen."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(modified="2024-07-20T08:00:00Z"))
    iocs = ingester.parse_bundle(bundle)
    assert iocs[0]["last_seen"].year == 2024
    assert iocs[0]["last_seen"].month == 7


def test_parse_bundle_labels_mapped_to_tags():
    """labels list is copied to tags."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(labels=["apt28", "phishing"]))
    iocs = ingester.parse_bundle(bundle)
    assert iocs[0]["tags"] == ["apt28", "phishing"]


def test_parse_bundle_description_truncated_at_500():
    """description longer than 500 chars is truncated."""
    long_desc = "x" * 600
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator(description=long_desc))
    iocs = ingester.parse_bundle(bundle)
    assert len(iocs[0]["description"]) == 500


def test_parse_bundle_description_uses_name_when_description_absent():
    """When description is absent, name field is used as description."""
    ingester = STIXFeedIngester(_make_config())
    obj = _make_indicator(description=None, name_field="Malicious IP")
    bundle = _make_bundle(obj)
    iocs = ingester.parse_bundle(bundle)
    assert iocs[0]["description"] == "Malicious IP"


def test_parse_bundle_is_active_always_true():
    """All parsed IOCs must have is_active=True."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator())
    iocs = ingester.parse_bundle(bundle)
    assert all(ioc["is_active"] is True for ioc in iocs)


def test_parse_bundle_multiple_indicators():
    """Multiple indicator objects in one bundle are all parsed."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(
        _make_indicator(pattern="[ipv4-addr:value = '10.0.0.1']"),
        _make_indicator(pattern="[domain-name:value = 'evil.com']"),
        _make_indicator(pattern="[url:value = 'http://bad.example.com/']"),
    )
    iocs = ingester.parse_bundle(bundle)
    assert len(iocs) == 3
    types = {ioc["ioc_type"] for ioc in iocs}
    assert types == {"ip", "domain", "url"}


# ---------------------------------------------------------------------------
# Section 6 — poll(): HTTP behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_poll_returns_bundle_on_success():
    """poll() returns the parsed JSON bundle on HTTP 200."""
    ingester = STIXFeedIngester(_make_config())
    expected_bundle = _make_bundle(_make_indicator())

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = expected_bundle
    mock_response.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        result = await ingester.poll()

    assert result == expected_bundle


@pytest.mark.asyncio
async def test_poll_returns_none_on_http_401():
    """poll() returns None on HTTP 401 (non-fatal)."""
    ingester = STIXFeedIngester(_make_config())

    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "401", request=MagicMock(), response=mock_response
    )

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        result = await ingester.poll()

    assert result is None


@pytest.mark.asyncio
async def test_poll_returns_none_on_http_404():
    """poll() returns None on HTTP 404 (non-fatal)."""
    ingester = STIXFeedIngester(_make_config())

    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "404", request=MagicMock(), response=mock_response
    )

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        result = await ingester.poll()

    assert result is None


@pytest.mark.asyncio
async def test_poll_returns_none_on_connection_error():
    """poll() returns None when the network connection fails (non-fatal)."""
    ingester = STIXFeedIngester(_make_config())

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        result = await ingester.poll()

    assert result is None


@pytest.mark.asyncio
async def test_poll_first_call_has_no_added_after():
    """First poll must not include the added_after query parameter."""
    ingester = STIXFeedIngester(_make_config())
    assert ingester._last_poll is None

    captured_params: list[dict] = []

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"objects": []}

    async def mock_get(url, *, headers=None, params=None):
        captured_params.append(params or {})
        return mock_response

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = mock_get

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        await ingester.poll()

    assert captured_params == [{}], "First poll must not send added_after"


@pytest.mark.asyncio
async def test_poll_subsequent_call_includes_added_after():
    """Subsequent polls must include added_after based on _last_poll."""
    ingester = STIXFeedIngester(_make_config())
    ingester._last_poll = datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

    captured_params: list[dict] = []

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"objects": []}

    async def mock_get(url, *, headers=None, params=None):
        captured_params.append(params or {})
        return mock_response

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = mock_get

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        await ingester.poll()

    assert "added_after" in captured_params[0]
    assert "2024-06-01" in captured_params[0]["added_after"]


@pytest.mark.asyncio
async def test_poll_updates_last_poll_on_success():
    """_last_poll is updated after a successful poll."""
    ingester = STIXFeedIngester(_make_config())
    assert ingester._last_poll is None

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"objects": []}

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        await ingester.poll()

    assert ingester._last_poll is not None


@pytest.mark.asyncio
async def test_poll_does_not_update_last_poll_on_http_error():
    """_last_poll must not be modified when the poll fails."""
    ingester = STIXFeedIngester(_make_config())
    original_last_poll = ingester._last_poll  # None

    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
        "500", request=MagicMock(), response=mock_response
    )

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        await ingester.poll()

    assert ingester._last_poll is original_last_poll


@pytest.mark.asyncio
async def test_poll_authorization_header_present_with_api_key():
    """Authorization: Bearer header is sent when api_key is set."""
    ingester = STIXFeedIngester(_make_config(api_key="my-secret"))

    captured_headers: list[dict] = []

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"objects": []}

    async def mock_get(url, *, headers=None, params=None):
        captured_headers.append(headers or {})
        return mock_response

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = mock_get

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        await ingester.poll()

    assert captured_headers[0].get("Authorization") == "Bearer my-secret"


@pytest.mark.asyncio
async def test_poll_no_authorization_header_when_api_key_empty():
    """Authorization header must be absent when api_key is empty string."""
    ingester = STIXFeedIngester(_make_config(api_key=""))

    captured_headers: list[dict] = []

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"objects": []}

    async def mock_get(url, *, headers=None, params=None):
        captured_headers.append(headers or {})
        return mock_response

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = mock_get

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        await ingester.poll()

    assert "Authorization" not in captured_headers[0]


@pytest.mark.asyncio
async def test_poll_accept_header_is_taxii_media_type():
    """Accept header must be application/taxii+json;version=2.1 on every poll."""
    ingester = STIXFeedIngester(_make_config())

    captured_headers: list[dict] = []

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"objects": []}

    async def mock_get(url, *, headers=None, params=None):
        captured_headers.append(headers or {})
        return mock_response

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = mock_get

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        await ingester.poll()

    assert captured_headers[0].get("Accept") == "application/taxii+json;version=2.1"


@pytest.mark.asyncio
async def test_poll_objects_url_uses_collection_id():
    """The objects URL must embed the collection_id from the feed config."""
    ingester = STIXFeedIngester(
        _make_config(taxii_url="https://taxii.example.com/api", collection_id="col-xyz")
    )

    captured_urls: list[str] = []

    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()
    mock_response.json.return_value = {"objects": []}

    async def mock_get(url, *, headers=None, params=None):
        captured_urls.append(url)
        return mock_response

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = mock_get

    with patch("app.services.stix_feed.httpx.AsyncClient", return_value=mock_client):
        await ingester.poll()

    assert "col-xyz" in captured_urls[0]
    assert captured_urls[0].endswith("/objects/")


# ---------------------------------------------------------------------------
# Section 7 — ingest()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_returns_zero_when_poll_fails():
    """ingest() returns (0, 0) when poll() returns None."""
    ingester = STIXFeedIngester(_make_config())

    with patch.object(ingester, "poll", new=AsyncMock(return_value=None)):
        created, skipped = await ingester.ingest()

    assert created == 0
    assert skipped == 0


@pytest.mark.asyncio
async def test_ingest_returns_zero_when_no_parseable_indicators():
    """ingest() returns (0, 0) when the bundle has no parseable indicators."""
    ingester = STIXFeedIngester(_make_config())
    empty_bundle = _make_bundle()  # no objects

    with patch.object(ingester, "poll", new=AsyncMock(return_value=empty_bundle)):
        created, skipped = await ingester.ingest()

    assert created == 0
    assert skipped == 0


@pytest.mark.asyncio
async def test_ingest_returns_created_skipped_from_bulk_create():
    """ingest() returns (created, skipped) as reported by IOCRepo.bulk_create."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator())

    mock_session = AsyncMock()
    mock_session_ctx = MagicMock()
    mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

    with (
        patch.object(ingester, "poll", new=AsyncMock(return_value=bundle)),
        patch("app.services.stix_feed.AsyncSessionLocal", return_value=mock_session_ctx),
        patch(
            "app.services.stix_feed.IOCRepo.bulk_create",
            new=AsyncMock(return_value=(5, 2)),
        ),
    ):
        created, skipped = await ingester.ingest()

    assert created == 5
    assert skipped == 2


@pytest.mark.asyncio
async def test_ingest_calls_bulk_create_with_ioc_dicts():
    """ingest() passes parsed IOC dicts to IOCRepo.bulk_create."""
    ingester = STIXFeedIngester(_make_config(name="my-feed"))
    bundle = _make_bundle(_make_indicator(pattern="[ipv4-addr:value = '5.6.7.8']"))

    bulk_create_calls: list[list[dict]] = []

    async def capture_bulk_create(session, items):
        bulk_create_calls.append(items)
        return len(items), 0

    mock_session = AsyncMock()
    mock_session_ctx = MagicMock()
    mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

    with (
        patch.object(ingester, "poll", new=AsyncMock(return_value=bundle)),
        patch("app.services.stix_feed.AsyncSessionLocal", return_value=mock_session_ctx),
        patch(
            "app.services.stix_feed.IOCRepo.bulk_create",
            side_effect=capture_bulk_create,
        ),
    ):
        await ingester.ingest()

    assert len(bulk_create_calls) == 1
    iocs = bulk_create_calls[0]
    assert len(iocs) == 1
    assert iocs[0]["ioc_type"] == "ip"
    assert iocs[0]["value"] == "5.6.7.8"
    assert iocs[0]["source"] == "my-feed"


@pytest.mark.asyncio
async def test_ingest_commits_session_after_bulk_create():
    """ingest() calls session.commit() after bulk_create succeeds."""
    ingester = STIXFeedIngester(_make_config())
    bundle = _make_bundle(_make_indicator())

    mock_session = AsyncMock()
    mock_session_ctx = MagicMock()
    mock_session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

    with (
        patch.object(ingester, "poll", new=AsyncMock(return_value=bundle)),
        patch("app.services.stix_feed.AsyncSessionLocal", return_value=mock_session_ctx),
        patch(
            "app.services.stix_feed.IOCRepo.bulk_create",
            new=AsyncMock(return_value=(1, 0)),
        ),
    ):
        await ingester.ingest()

    mock_session.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# Section 8 — stix_feed_poller()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_poller_exits_immediately_with_no_feeds():
    """stix_feed_poller() returns without blocking when configs is empty."""
    # Should complete without awaiting asyncio.sleep
    await asyncio.wait_for(stix_feed_poller([]), timeout=2.0)


@pytest.mark.asyncio
async def test_poller_calls_ingest_for_due_feed():
    """stix_feed_poller() calls ingest() for a feed when next_poll time is reached."""
    config = _make_config(poll_interval=3600)

    ingest_calls: list[str] = []

    async def mock_ingest():
        ingest_calls.append(config.name)
        return 0, 0

    # Patch time.monotonic so the feed is immediately due, then advance time
    # to exit the loop after one iteration.
    call_count = 0
    base_time = 1000.0

    def mock_monotonic():
        nonlocal call_count
        call_count += 1
        # Return base_time on first several calls (feed is due),
        # then a large value so sleep(60) is mocked to exit
        return base_time

    async def mock_sleep(seconds):
        # After first sleep, cancel the task to end the loop
        raise asyncio.CancelledError

    with (
        patch("app.services.stix_feed.time.monotonic", side_effect=mock_monotonic),
        patch("app.services.stix_feed.asyncio.sleep", side_effect=mock_sleep),
        patch(
            "app.services.stix_feed.STIXFeedIngester.ingest",
            side_effect=mock_ingest,
        ),
    ):
        with pytest.raises(asyncio.CancelledError):
            await stix_feed_poller([config])

    assert config.name in ingest_calls, "ingest() must be called for the due feed"


@pytest.mark.asyncio
async def test_poller_continues_after_ingest_exception():
    """stix_feed_poller() catches exceptions from ingest() and continues the loop."""
    config = _make_config(poll_interval=3600)

    ingest_call_count = 0

    async def failing_ingest():
        nonlocal ingest_call_count
        ingest_call_count += 1
        raise RuntimeError("TAXII server unreachable")

    sleep_call_count = 0

    async def mock_sleep(seconds):
        nonlocal sleep_call_count
        sleep_call_count += 1
        if sleep_call_count >= 2:
            raise asyncio.CancelledError

    # Make monotonic always return a time that triggers the feed
    with (
        patch("app.services.stix_feed.time.monotonic", return_value=9999.0),
        patch("app.services.stix_feed.asyncio.sleep", side_effect=mock_sleep),
        patch(
            "app.services.stix_feed.STIXFeedIngester.ingest",
            side_effect=failing_ingest,
        ),
    ):
        with pytest.raises(asyncio.CancelledError):
            await stix_feed_poller([config])

    # ingest() should have been called at least once despite raising
    assert ingest_call_count >= 1, "ingest() must be called even if it previously failed"
