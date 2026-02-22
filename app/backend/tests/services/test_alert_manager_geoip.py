"""Tests for AlertManager GeoIP enrichment (feature 9.8).

Coverage:
  - _load_geoip_reader(): sets _GEOIP_NOT_AVAILABLE when geoip_db_path is None
  - _load_geoip_reader(): sets _GEOIP_NOT_AVAILABLE when database file cannot be opened
  - _load_geoip_reader(): stores live reader when database file opens successfully
  - _collect_public_ips(): returns empty list when host is empty and snapshot has no IPs
  - _collect_public_ips(): skips private IPv4 addresses (RFC1918)
  - _collect_public_ips(): skips loopback addresses (127.x.x.x)
  - _collect_public_ips(): skips link-local addresses (169.254.x.x)
  - _collect_public_ips(): includes globally-routable public IPs
  - _collect_public_ips(): extracts IP from alert.host field
  - _collect_public_ips(): extracts IP from event_snapshot src_ip
  - _collect_public_ips(): extracts IP from event_snapshot dst_ip
  - _collect_public_ips(): extracts IP from OCSF src.ip nested field
  - _collect_public_ips(): extracts IP from OCSF dst.ip nested field
  - _collect_public_ips(): deduplicates duplicate IPs across fields
  - _collect_public_ips(): ignores non-IP strings (hostnames)
  - _geoip_reader_lookup(): returns structured dict on success
  - _geoip_reader_lookup(): returns None when AddressNotFoundError raised
  - _geoip_reader_lookup(): returns None on any other reader exception
  - _geoip_reader_lookup(): result has ip, country_code, country, region, city, latitude, longitude
  - _geoip_for_ip(): returns cached result from Valkey on cache hit
  - _geoip_for_ip(): calls reader and caches result on cache miss
  - _geoip_for_ip(): returns None and does not cache when reader returns None
  - _geoip_for_ip(): proceeds to DB lookup when Valkey.get raises
  - _geoip_for_ip(): returns result even when Valkey.set raises (non-fatal)
  - _lookup_geoip(): returns None when geoip_db_path is not configured
  - _lookup_geoip(): returns None when database file cannot be loaded
  - _lookup_geoip(): returns None when no public IPs found
  - _lookup_geoip(): returns None when private-only IPs in alert
  - _lookup_geoip(): returns geo dict for alert.host public IP
  - _lookup_geoip(): returns geo dict for src_ip from event_snapshot
  - _lookup_geoip(): returns geo dict for dst_ip from event_snapshot
  - _lookup_geoip(): returns geo dict for OCSF src.ip nested field
  - _lookup_geoip(): returns geo dict for OCSF dst.ip nested field
  - _lookup_geoip(): returns first match when multiple public IPs are present
  - _lookup_geoip(): returns None when all IPs are absent from database
  - _lookup_geoip(): fail-open — returns None on unexpected exception
  - _enrich(): geo_ip field populated from _lookup_geoip result
  - _enrich(): geo_ip is None when _lookup_geoip returns None
  - process(): geo_ip appears in published payload when lookup succeeds
  - process(): geo_ip is None in published payload when lookup returns None
  - process(): GeoIP lookup failure does not block the pipeline
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.engine.sigma_engine import SigmaAlert
from app.pipeline.queue import InMemoryQueue
from app.services.alert_manager import AlertManager, _GEOIP_NOT_AVAILABLE


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc).isoformat()

_ALERT_DICT = {
    "id": "alert-geo-001",
    "rule_id": "sigma-scan",
    "rule_title": "Port Scan Detected",
    "level": "medium",
    "severity_id": 3,
    "technique_ids": ["T1046"],
    "tactic_ids": ["Discovery"],
    "host": "1.2.3.4",
    "time": _NOW,
    "event_snapshot": {},
}

_GEO_RESULT = {
    "ip": "1.2.3.4",
    "country_code": "US",
    "country": "United States",
    "region": "California",
    "city": "San Francisco",
    "latitude": 37.7749,
    "longitude": -122.4194,
}


def _make_manager() -> AlertManager:
    """Create a minimal AlertManager with mocked Valkey and IOC matcher."""
    queue = InMemoryQueue()
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = queue
    mgr._dispatcher = None
    mgr._valkey = MagicMock()
    mgr._valkey.set = AsyncMock(return_value=True)
    mgr._valkey.aclose = AsyncMock()
    mgr._geoip_reader = None
    # Mock IOC matcher so _enrich() doesn't require the real IOCMatcher
    mgr._ioc_matcher = MagicMock()
    mgr._ioc_matcher.match_event = AsyncMock(return_value=[])
    mgr._ioc_matcher.update_hits = AsyncMock()
    return mgr


def _make_alert(
    host: str = "1.2.3.4",
    event_snapshot: dict | None = None,
) -> SigmaAlert:
    return SigmaAlert(
        id="a-geo-1",
        rule_id="sigma-scan",
        rule_title="Port Scan",
        level="medium",
        severity_id=3,
        technique_ids=["T1046"],
        tactic_ids=["Discovery"],
        host=host,
        event_snapshot=event_snapshot or {},
    )


def _make_mock_reader(
    city_result: dict | None = None,
    raises: Exception | None = None,
) -> MagicMock:
    """Build a mock geoip2.database.Reader.

    If *raises* is set, reader.city() will raise that exception.
    Otherwise reader.city() returns a mock response built from *city_result*.
    """
    reader = MagicMock()
    if raises is not None:
        reader.city.side_effect = raises
        return reader

    data = city_result or {
        "country_iso_code": "US",
        "country_name": "United States",
        "region": "California",
        "city": "San Francisco",
        "latitude": 37.7749,
        "longitude": -122.4194,
    }

    response = MagicMock()
    response.country.iso_code = data.get("country_iso_code", "US")
    response.country.name = data.get("country_name", "United States")
    subdivision = MagicMock()
    subdivision.name = data.get("region")
    response.subdivisions.most_specific = subdivision
    response.city.name = data.get("city")
    response.location.latitude = data.get("latitude", 0.0)
    response.location.longitude = data.get("longitude", 0.0)

    reader.city.return_value = response
    return reader


# ---------------------------------------------------------------------------
# _load_geoip_reader()
# ---------------------------------------------------------------------------


def test_load_geoip_reader_no_path_sets_not_available():
    """Sets _GEOIP_NOT_AVAILABLE when geoip_db_path is None."""
    mgr = _make_manager()
    with patch("app.services.alert_manager.settings") as mock_settings:
        mock_settings.geoip_db_path = None
        mgr._load_geoip_reader()
    assert mgr._geoip_reader is _GEOIP_NOT_AVAILABLE


def test_load_geoip_reader_file_not_found_sets_not_available(tmp_path):
    """Sets _GEOIP_NOT_AVAILABLE when the mmdb file cannot be opened."""
    mgr = _make_manager()
    nonexistent = str(tmp_path / "missing.mmdb")
    with patch("app.services.alert_manager.settings") as mock_settings:
        mock_settings.geoip_db_path = nonexistent
        with patch("geoip2.database.Reader", side_effect=FileNotFoundError("not found")):
            mgr._load_geoip_reader()
    assert mgr._geoip_reader is _GEOIP_NOT_AVAILABLE


def test_load_geoip_reader_success_stores_reader(tmp_path):
    """Stores the live reader instance when the database opens successfully."""
    mgr = _make_manager()
    db_path = str(tmp_path / "GeoLite2-City.mmdb")
    mock_reader = MagicMock()
    with patch("app.services.alert_manager.settings") as mock_settings:
        mock_settings.geoip_db_path = db_path
        with patch("geoip2.database.Reader", return_value=mock_reader):
            mgr._load_geoip_reader()
    assert mgr._geoip_reader is mock_reader


# ---------------------------------------------------------------------------
# _collect_public_ips()
# ---------------------------------------------------------------------------


def test_collect_public_ips_empty_alert():
    """Returns empty list when host is empty and snapshot has no IPs."""
    mgr = _make_manager()
    alert = _make_alert(host="", event_snapshot={})
    assert mgr._collect_public_ips(alert) == []


def test_collect_public_ips_skips_private_ipv4():
    """Private RFC1918 addresses are excluded."""
    mgr = _make_manager()
    for private in ["10.0.0.1", "192.168.1.100", "172.16.0.1"]:
        alert = _make_alert(host=private)
        assert mgr._collect_public_ips(alert) == [], f"{private} should be excluded"


def test_collect_public_ips_skips_loopback():
    """Loopback addresses (127.x.x.x) are excluded."""
    mgr = _make_manager()
    alert = _make_alert(host="127.0.0.1")
    assert mgr._collect_public_ips(alert) == []


def test_collect_public_ips_skips_link_local():
    """Link-local addresses (169.254.x.x) are excluded."""
    mgr = _make_manager()
    alert = _make_alert(host="169.254.1.5")
    assert mgr._collect_public_ips(alert) == []


def test_collect_public_ips_includes_public_ip():
    """A globally-routable public IP is included."""
    mgr = _make_manager()
    alert = _make_alert(host="8.8.8.8")
    assert mgr._collect_public_ips(alert) == ["8.8.8.8"]


def test_collect_public_ips_host_field_is_first():
    """IP from alert.host is the first candidate."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4", event_snapshot={"src_ip": "5.6.7.8"})
    ips = mgr._collect_public_ips(alert)
    assert ips[0] == "1.2.3.4"


def test_collect_public_ips_src_ip_from_snapshot():
    """Extracts src_ip from event_snapshot."""
    mgr = _make_manager()
    alert = _make_alert(host="", event_snapshot={"src_ip": "5.6.7.8"})
    assert "5.6.7.8" in mgr._collect_public_ips(alert)


def test_collect_public_ips_dst_ip_from_snapshot():
    """Extracts dst_ip from event_snapshot."""
    mgr = _make_manager()
    alert = _make_alert(host="", event_snapshot={"dst_ip": "9.10.11.12"})
    assert "9.10.11.12" in mgr._collect_public_ips(alert)


def test_collect_public_ips_ocsf_src_ip():
    """Extracts src.ip from OCSF nested structure."""
    mgr = _make_manager()
    alert = _make_alert(host="", event_snapshot={"src": {"ip": "13.14.15.16"}})
    assert "13.14.15.16" in mgr._collect_public_ips(alert)


def test_collect_public_ips_ocsf_dst_ip():
    """Extracts dst.ip from OCSF nested structure."""
    mgr = _make_manager()
    alert = _make_alert(host="", event_snapshot={"dst": {"ip": "17.18.19.20"}})
    assert "17.18.19.20" in mgr._collect_public_ips(alert)


def test_collect_public_ips_deduplicates():
    """The same public IP appearing in multiple fields is returned only once."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4", event_snapshot={"src_ip": "1.2.3.4"})
    ips = mgr._collect_public_ips(alert)
    assert ips.count("1.2.3.4") == 1


def test_collect_public_ips_ignores_hostnames():
    """Non-IP strings (hostnames) are silently ignored."""
    mgr = _make_manager()
    alert = _make_alert(host="some-server.internal", event_snapshot={})
    assert mgr._collect_public_ips(alert) == []


# ---------------------------------------------------------------------------
# _geoip_reader_lookup()
# ---------------------------------------------------------------------------


def test_geoip_reader_lookup_returns_structured_dict():
    """Returns a dict with all required fields on successful lookup."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    result = mgr._geoip_reader_lookup("1.2.3.4")
    assert result is not None
    assert result["ip"] == "1.2.3.4"
    assert result["country_code"] == "US"
    assert result["country"] == "United States"
    assert result["city"] == "San Francisco"
    assert result["region"] == "California"
    assert isinstance(result["latitude"], float)
    assert isinstance(result["longitude"], float)


def test_geoip_reader_lookup_result_has_all_keys():
    """Result dict contains exactly the expected keys."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    result = mgr._geoip_reader_lookup("1.2.3.4")
    assert set(result.keys()) == {
        "ip", "country_code", "country", "region", "city", "latitude", "longitude"
    }


def test_geoip_reader_lookup_returns_none_on_address_not_found():
    """Returns None when the IP is not in the database."""
    import geoip2.errors
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader(raises=geoip2.errors.AddressNotFoundError("not found"))
    result = mgr._geoip_reader_lookup("1.2.3.4")
    assert result is None


def test_geoip_reader_lookup_returns_none_on_generic_exception():
    """Returns None on any unexpected reader exception."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader(raises=RuntimeError("mmdb error"))
    result = mgr._geoip_reader_lookup("1.2.3.4")
    assert result is None


# ---------------------------------------------------------------------------
# _geoip_for_ip()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_geoip_for_ip_returns_cached_result():
    """Returns the cached result from Valkey without calling the reader."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    cached = json.dumps(_GEO_RESULT)
    mgr._valkey.get = AsyncMock(return_value=cached)

    result = await mgr._geoip_for_ip("1.2.3.4")

    assert result == _GEO_RESULT
    mgr._geoip_reader.city.assert_not_called()


@pytest.mark.asyncio
async def test_geoip_for_ip_calls_reader_on_cache_miss():
    """Calls the mmdb reader when Valkey returns None (cache miss)."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    mgr._valkey.get = AsyncMock(return_value=None)
    mgr._valkey.set = AsyncMock(return_value=True)

    result = await mgr._geoip_for_ip("1.2.3.4")

    assert result is not None
    mgr._geoip_reader.city.assert_called_once_with("1.2.3.4")


@pytest.mark.asyncio
async def test_geoip_for_ip_writes_cache_after_db_hit():
    """Writes the result to Valkey after a successful mmdb lookup."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    mgr._valkey.get = AsyncMock(return_value=None)
    mock_set = AsyncMock(return_value=True)
    mgr._valkey.set = mock_set

    await mgr._geoip_for_ip("1.2.3.4")

    mock_set.assert_awaited()
    # At least one call should be for the GeoIP cache key (not dedup)
    geoip_calls = [
        c for c in mock_set.call_args_list
        if c.args and "mxtac:geoip:1.2.3.4" in str(c.args[0])
    ]
    assert len(geoip_calls) == 1


@pytest.mark.asyncio
async def test_geoip_for_ip_returns_none_when_reader_miss():
    """Returns None and does not cache when the reader returns None (IP not in DB)."""
    import geoip2.errors
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader(raises=geoip2.errors.AddressNotFoundError("not found"))
    mgr._valkey.get = AsyncMock(return_value=None)
    mock_set = AsyncMock()
    mgr._valkey.set = mock_set

    result = await mgr._geoip_for_ip("1.2.3.4")

    assert result is None
    # Should not have written to GeoIP cache key
    geoip_calls = [
        c for c in mock_set.call_args_list
        if c.args and "mxtac:geoip:" in str(c.args[0])
    ]
    assert len(geoip_calls) == 0


@pytest.mark.asyncio
async def test_geoip_for_ip_proceeds_to_db_when_cache_get_raises():
    """Falls through to DB lookup when Valkey.get raises an exception."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    mgr._valkey.get = AsyncMock(side_effect=Exception("Valkey down"))
    mgr._valkey.set = AsyncMock(return_value=True)

    result = await mgr._geoip_for_ip("1.2.3.4")

    assert result is not None
    mgr._geoip_reader.city.assert_called_once()


@pytest.mark.asyncio
async def test_geoip_for_ip_returns_result_when_cache_set_raises():
    """Returns the lookup result even when Valkey.set raises (cache write non-fatal)."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    mgr._valkey.get = AsyncMock(return_value=None)
    mgr._valkey.set = AsyncMock(side_effect=Exception("Valkey write failed"))

    result = await mgr._geoip_for_ip("1.2.3.4")

    assert result is not None


# ---------------------------------------------------------------------------
# _lookup_geoip() — reader not configured / unavailable
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_geoip_returns_none_when_db_not_configured():
    """Returns None when geoip_db_path is not set."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")

    with patch("app.services.alert_manager.settings") as mock_settings:
        mock_settings.geoip_db_path = None
        result = await mgr._lookup_geoip(alert)

    assert result is None
    assert mgr._geoip_reader is _GEOIP_NOT_AVAILABLE


@pytest.mark.asyncio
async def test_lookup_geoip_returns_none_when_db_file_missing():
    """Returns None when the mmdb file cannot be opened."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")

    with patch("app.services.alert_manager.settings") as mock_settings:
        mock_settings.geoip_db_path = "/nonexistent/GeoLite2-City.mmdb"
        with patch("geoip2.database.Reader", side_effect=FileNotFoundError("no file")):
            result = await mgr._lookup_geoip(alert)

    assert result is None


@pytest.mark.asyncio
async def test_lookup_geoip_skips_load_when_already_not_available():
    """Does not try to reload when reader is already _GEOIP_NOT_AVAILABLE."""
    mgr = _make_manager()
    mgr._geoip_reader = _GEOIP_NOT_AVAILABLE
    alert = _make_alert(host="1.2.3.4")

    with patch.object(mgr, "_load_geoip_reader") as mock_load:
        result = await mgr._lookup_geoip(alert)

    mock_load.assert_not_called()
    assert result is None


# ---------------------------------------------------------------------------
# _lookup_geoip() — no public IPs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_geoip_returns_none_when_no_public_ips():
    """Returns None when the alert contains no IP fields."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    alert = _make_alert(host="", event_snapshot={})

    result = await mgr._lookup_geoip(alert)

    assert result is None
    mgr._geoip_reader.city.assert_not_called()


@pytest.mark.asyncio
async def test_lookup_geoip_returns_none_for_private_ip_only():
    """Returns None when the alert only contains private/RFC1918 IPs."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    alert = _make_alert(host="10.0.0.5", event_snapshot={"src_ip": "192.168.0.1"})

    result = await mgr._lookup_geoip(alert)

    assert result is None
    mgr._geoip_reader.city.assert_not_called()


# ---------------------------------------------------------------------------
# _lookup_geoip() — successful lookups
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_geoip_returns_geo_for_public_host():
    """Returns geo dict when alert.host is a public IP."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    mgr._valkey.get = AsyncMock(return_value=None)
    mgr._valkey.set = AsyncMock(return_value=True)
    alert = _make_alert(host="1.2.3.4")

    result = await mgr._lookup_geoip(alert)

    assert result is not None
    assert result["ip"] == "1.2.3.4"
    assert result["country_code"] == "US"


@pytest.mark.asyncio
async def test_lookup_geoip_returns_geo_for_src_ip_in_snapshot():
    """Returns geo dict when src_ip in event_snapshot is a public IP."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    mgr._valkey.get = AsyncMock(return_value=None)
    mgr._valkey.set = AsyncMock(return_value=True)
    alert = _make_alert(host="", event_snapshot={"src_ip": "5.6.7.8"})

    result = await mgr._lookup_geoip(alert)

    assert result is not None
    assert result["ip"] == "5.6.7.8"


@pytest.mark.asyncio
async def test_lookup_geoip_returns_geo_for_dst_ip_in_snapshot():
    """Returns geo dict when dst_ip in event_snapshot is a public IP."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    mgr._valkey.get = AsyncMock(return_value=None)
    mgr._valkey.set = AsyncMock(return_value=True)
    alert = _make_alert(host="", event_snapshot={"dst_ip": "9.10.11.12"})

    result = await mgr._lookup_geoip(alert)

    assert result is not None
    assert result["ip"] == "9.10.11.12"


@pytest.mark.asyncio
async def test_lookup_geoip_returns_geo_for_ocsf_src_ip():
    """Returns geo dict for OCSF src.ip nested field."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    mgr._valkey.get = AsyncMock(return_value=None)
    mgr._valkey.set = AsyncMock(return_value=True)
    alert = _make_alert(host="", event_snapshot={"src": {"ip": "13.14.15.16"}})

    result = await mgr._lookup_geoip(alert)

    assert result is not None
    assert result["ip"] == "13.14.15.16"


@pytest.mark.asyncio
async def test_lookup_geoip_returns_geo_for_ocsf_dst_ip():
    """Returns geo dict for OCSF dst.ip nested field."""
    mgr = _make_manager()
    mgr._geoip_reader = _make_mock_reader()
    mgr._valkey.get = AsyncMock(return_value=None)
    mgr._valkey.set = AsyncMock(return_value=True)
    alert = _make_alert(host="", event_snapshot={"dst": {"ip": "17.18.19.20"}})

    result = await mgr._lookup_geoip(alert)

    assert result is not None
    assert result["ip"] == "17.18.19.20"


@pytest.mark.asyncio
async def test_lookup_geoip_returns_first_match_for_multiple_public_ips():
    """Returns geo data for the first public IP that has a result."""
    import geoip2.errors
    mgr = _make_manager()

    call_count = 0

    def _side_effect(ip: str) -> Any:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise geoip2.errors.AddressNotFoundError()
        response = MagicMock()
        response.country.iso_code = "DE"
        response.country.name = "Germany"
        response.subdivisions.most_specific.name = "Bavaria"
        response.city.name = "Munich"
        response.location.latitude = 48.1351
        response.location.longitude = 11.5820
        return response

    reader = MagicMock()
    reader.city.side_effect = _side_effect
    mgr._geoip_reader = reader
    mgr._valkey.get = AsyncMock(return_value=None)
    mgr._valkey.set = AsyncMock(return_value=True)

    alert = _make_alert(host="1.2.3.4", event_snapshot={"src_ip": "5.6.7.8"})

    result = await mgr._lookup_geoip(alert)

    assert result is not None
    assert result["ip"] == "5.6.7.8"
    assert result["country_code"] == "DE"


@pytest.mark.asyncio
async def test_lookup_geoip_returns_none_when_all_ips_absent_from_db():
    """Returns None when all candidate IPs are not in the mmdb database."""
    import geoip2.errors
    mgr = _make_manager()
    reader = MagicMock()
    reader.city.side_effect = geoip2.errors.AddressNotFoundError("not found")
    mgr._geoip_reader = reader
    mgr._valkey.get = AsyncMock(return_value=None)
    mgr._valkey.set = AsyncMock(return_value=True)

    alert = _make_alert(host="1.2.3.4", event_snapshot={"src_ip": "5.6.7.8"})

    result = await mgr._lookup_geoip(alert)

    assert result is None


# ---------------------------------------------------------------------------
# _lookup_geoip() — fail-open behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_geoip_fail_open_on_unexpected_exception():
    """Returns None (fail-open) when an unexpected exception occurs."""
    mgr = _make_manager()
    mgr._geoip_reader = _GEOIP_NOT_AVAILABLE
    alert = _make_alert(host="1.2.3.4")

    with patch.object(mgr, "_collect_public_ips", side_effect=RuntimeError("boom")):
        result = await mgr._lookup_geoip(alert)

    assert result is None


# ---------------------------------------------------------------------------
# _enrich() integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrich_geo_ip_field_populated_when_match():
    """_enrich() embeds geo_ip dict when _lookup_geoip returns a result."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")

    with (
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=_GEO_RESULT)),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
    ):
        enriched = await mgr._enrich(alert)

    assert enriched["geo_ip"] == _GEO_RESULT


@pytest.mark.asyncio
async def test_enrich_geo_ip_is_none_when_no_match():
    """_enrich() has geo_ip=None when _lookup_geoip returns None."""
    mgr = _make_manager()
    alert = _make_alert(host="10.0.0.1")

    with (
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
    ):
        enriched = await mgr._enrich(alert)

    assert enriched["geo_ip"] is None


# ---------------------------------------------------------------------------
# process() end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_geo_ip_in_published_payload():
    """Published enriched alert contains geo_ip when lookup succeeds."""
    mgr = _make_manager()
    published: list[dict] = []

    async def _capture(_topic, msg):
        published.append(msg)

    with (
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=_GEO_RESULT)),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_persist_to_db", new=AsyncMock()),
        patch.object(AlertManager, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(mgr._queue, "publish", side_effect=_capture),
    ):
        await mgr.process(_ALERT_DICT)

    assert len(published) == 1
    assert published[0]["geo_ip"] == _GEO_RESULT


@pytest.mark.asyncio
async def test_process_geo_ip_none_in_published_payload():
    """Published enriched alert has geo_ip=None when lookup returns None."""
    mgr = _make_manager()
    published: list[dict] = []

    async def _capture(_topic, msg):
        published.append(msg)

    with (
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_persist_to_db", new=AsyncMock()),
        patch.object(AlertManager, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(mgr._queue, "publish", side_effect=_capture),
    ):
        await mgr.process(_ALERT_DICT)

    assert len(published) == 1
    assert published[0]["geo_ip"] is None


@pytest.mark.asyncio
async def test_process_geoip_failure_does_not_block_pipeline():
    """Even when _lookup_geoip fails (returns None), process() publishes the alert."""
    mgr = _make_manager()
    published: list[dict] = []

    async def _capture(_topic, msg):
        published.append(msg)

    with (
        patch.object(AlertManager, "_lookup_geoip", new=AsyncMock(return_value=None)),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_persist_to_db", new=AsyncMock()),
        patch.object(AlertManager, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(mgr._queue, "publish", side_effect=_capture),
    ):
        await mgr.process(_ALERT_DICT)

    assert len(published) == 1
