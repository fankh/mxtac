"""Tests for AlertManager threat intel enrichment (feature 9.7).

Coverage:
  - _lookup_threat_intel(): returns None when no IOC candidates can be extracted
  - _lookup_threat_intel(): returns None when all lookups produce empty results
  - _lookup_threat_intel(): returns match dict when host matches an active IP IOC
  - _lookup_threat_intel(): returns match dict when host matches an active domain IOC
  - _lookup_threat_intel(): returns match dict for src_ip in event_snapshot
  - _lookup_threat_intel(): returns match dict for dst_ip in event_snapshot
  - _lookup_threat_intel(): returns match dict for domain in event_snapshot
  - _lookup_threat_intel(): returns match dict for hostname in event_snapshot
  - _lookup_threat_intel(): returns match dict for hash_md5 in event_snapshot
  - _lookup_threat_intel(): returns match dict for hash_sha256 in event_snapshot
  - _lookup_threat_intel(): returns match dict for OCSF src.ip nested field
  - _lookup_threat_intel(): returns match dict for OCSF dst.ip nested field
  - _lookup_threat_intel(): returns match dict for OCSF process.file.hash_md5 nested field
  - _lookup_threat_intel(): returns match dict for OCSF process.file.hash_sha256 nested field
  - _lookup_threat_intel(): skips inactive IOCs (is_active=False)
  - _lookup_threat_intel(): increments hit count for each matched active IOC
  - _lookup_threat_intel(): commits session only when there are matches
  - _lookup_threat_intel(): does NOT commit session when no matches found
  - _lookup_threat_intel(): matched list contains ioc_id, ioc_type, value, severity, confidence, source, tags, description
  - _lookup_threat_intel(): ioc_count equals number of matched IOCs
  - _lookup_threat_intel(): highest_severity reflects the most severe matched IOC
  - _lookup_threat_intel(): highest_severity ordering: low < medium < high < critical
  - _lookup_threat_intel(): multiple matches — highest_severity picks the worst
  - _lookup_threat_intel(): fail-open — returns None when DB raises
  - _lookup_threat_intel(): fail-open — returns None when AsyncSessionLocal raises
  - _lookup_threat_intel(): fail-open — returns None when IOCRepo raises
  - _enrich(): threat_intel field populated from _lookup_threat_intel result
  - _enrich(): threat_intel is None when no IOC matches (pass-through)
  - process(): threat_intel appears in the published payload when IOC matches
  - process(): threat_intel is None in published payload when no IOC matches
  - process(): threat_intel lookup failure does not block the pipeline
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.engine.sigma_engine import SigmaAlert
from app.pipeline.queue import InMemoryQueue
from app.services.alert_manager import AlertManager


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc).isoformat()

_ALERT_DICT = {
    "id": "alert-ti-001",
    "rule_id": "sigma-mimikatz",
    "rule_title": "Mimikatz Detected",
    "level": "high",
    "severity_id": 4,
    "technique_ids": ["T1003.001"],
    "tactic_ids": ["Credential Access"],
    "host": "192.168.1.10",
    "time": _NOW,
    "event_snapshot": {},
}


def _make_manager(valkey_set_return=True) -> AlertManager:
    """Create a minimal AlertManager with mocked Valkey (new alert by default)."""
    queue = InMemoryQueue()
    mgr = AlertManager.__new__(AlertManager)
    mgr._queue = queue
    mgr._dispatcher = None
    mgr._valkey = MagicMock()
    mgr._valkey.set = AsyncMock(return_value=valkey_set_return)
    mgr._valkey.aclose = AsyncMock()
    return mgr


def _make_session_ctx(session=None):
    """Return an async context-manager mock wrapping *session*."""
    mock_ctx = AsyncMock()
    mock_session = session or AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    mock_ctx._session = mock_session
    return mock_ctx


def _make_ioc(
    ioc_id: int = 1,
    ioc_type: str = "ip",
    value: str = "192.168.1.10",
    severity: str = "high",
    confidence: int = 80,
    source: str = "opencti",
    tags: list | None = None,
    description: str = "Known C2 IP",
    is_active: bool = True,
) -> MagicMock:
    """Build a mock IOC object with the given attributes."""
    ioc = MagicMock()
    ioc.id = ioc_id
    ioc.ioc_type = ioc_type
    ioc.value = value
    ioc.severity = severity
    ioc.confidence = confidence
    ioc.source = source
    ioc.tags = tags if tags is not None else ["apt28"]
    ioc.description = description
    ioc.is_active = is_active
    return ioc


def _make_alert(
    host: str = "192.168.1.10",
    event_snapshot: dict | None = None,
) -> SigmaAlert:
    return SigmaAlert(
        id="a-ti-1",
        rule_id="sigma-mimikatz",
        rule_title="Mimikatz",
        level="high",
        severity_id=4,
        technique_ids=["T1003.001"],
        tactic_ids=["Credential Access"],
        host=host,
        event_snapshot=event_snapshot or {},
    )


# ---------------------------------------------------------------------------
# _lookup_threat_intel() — no candidates / no matches
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_threat_intel_no_candidates_empty_host_and_snapshot():
    """Returns None when host is empty and event_snapshot has no relevant fields."""
    mgr = _make_manager()
    alert = _make_alert(host="", event_snapshot={})

    # IOCRepo.bulk_lookup should never be called when there are no candidates.
    with patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=AsyncMock(return_value=[])) as mock_lookup:
        result = await mgr._lookup_threat_intel(alert)

    assert result is None
    mock_lookup.assert_not_called()


@pytest.mark.asyncio
async def test_lookup_threat_intel_no_matches_returns_none():
    """Returns None when bulk_lookup finds no active IOCs."""
    mgr = _make_manager()
    alert = _make_alert(host="10.0.0.1")
    ctx = _make_session_ctx()

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=AsyncMock(return_value=[])),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is None


@pytest.mark.asyncio
async def test_lookup_threat_intel_no_matches_does_not_commit():
    """Session.commit() must NOT be called when there are no matches."""
    mgr = _make_manager()
    alert = _make_alert(host="10.0.0.1")
    mock_session = AsyncMock()
    ctx = _make_session_ctx(mock_session)

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=AsyncMock(return_value=[])),
    ):
        await mgr._lookup_threat_intel(alert)

    mock_session.commit.assert_not_awaited()


# ---------------------------------------------------------------------------
# _lookup_threat_intel() — host matching
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_threat_intel_host_as_ip_match():
    """Matches when the alert host is a known malicious IP."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="ip", value="1.2.3.4", severity="high")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip" and "1.2.3.4" in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None
    assert result["ioc_count"] == 1
    assert result["matched"][0]["ioc_type"] == "ip"
    assert result["matched"][0]["value"] == "1.2.3.4"


@pytest.mark.asyncio
async def test_lookup_threat_intel_host_as_domain_match():
    """Matches when the alert host is a known malicious domain."""
    mgr = _make_manager()
    alert = _make_alert(host="evil.example.com")
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="domain", value="evil.example.com", severity="critical")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "domain" and "evil.example.com" in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None
    assert result["highest_severity"] == "critical"


# ---------------------------------------------------------------------------
# _lookup_threat_intel() — event_snapshot field extraction
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_threat_intel_src_ip_from_snapshot():
    """Matches when src_ip in event_snapshot is a known IOC."""
    mgr = _make_manager()
    alert = _make_alert(host="safe-host", event_snapshot={"src_ip": "5.5.5.5"})
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="ip", value="5.5.5.5")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip" and "5.5.5.5" in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None
    assert result["matched"][0]["value"] == "5.5.5.5"


@pytest.mark.asyncio
async def test_lookup_threat_intel_dst_ip_from_snapshot():
    """Matches when dst_ip in event_snapshot is a known IOC."""
    mgr = _make_manager()
    alert = _make_alert(host="safe-host", event_snapshot={"dst_ip": "6.6.6.6"})
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="ip", value="6.6.6.6")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip" and "6.6.6.6" in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None
    assert result["matched"][0]["value"] == "6.6.6.6"


@pytest.mark.asyncio
async def test_lookup_threat_intel_domain_from_snapshot():
    """Matches when domain in event_snapshot is a known IOC."""
    mgr = _make_manager()
    alert = _make_alert(host="safe-host", event_snapshot={"domain": "malware.c2.com"})
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="domain", value="malware.c2.com")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "domain" and "malware.c2.com" in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None


@pytest.mark.asyncio
async def test_lookup_threat_intel_hostname_from_snapshot():
    """Matches when hostname in event_snapshot is a known domain IOC."""
    mgr = _make_manager()
    alert = _make_alert(host="safe-host", event_snapshot={"hostname": "bad.domain.org"})
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="domain", value="bad.domain.org")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "domain" and "bad.domain.org" in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None


@pytest.mark.asyncio
async def test_lookup_threat_intel_hash_md5_from_snapshot():
    """Matches when hash_md5 in event_snapshot is a known IOC."""
    mgr = _make_manager()
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    alert = _make_alert(host="safe-host", event_snapshot={"hash_md5": md5})
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="hash_md5", value=md5)

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "hash_md5" and md5 in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None
    assert result["matched"][0]["ioc_type"] == "hash_md5"


@pytest.mark.asyncio
async def test_lookup_threat_intel_hash_sha256_from_snapshot():
    """Matches when hash_sha256 in event_snapshot is a known IOC."""
    mgr = _make_manager()
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    alert = _make_alert(host="safe-host", event_snapshot={"hash_sha256": sha256})
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="hash_sha256", value=sha256)

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "hash_sha256" and sha256 in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None
    assert result["matched"][0]["ioc_type"] == "hash_sha256"


# ---------------------------------------------------------------------------
# _lookup_threat_intel() — OCSF nested fields
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_threat_intel_ocsf_src_ip():
    """Matches when OCSF src.ip nested field is a known IP IOC."""
    mgr = _make_manager()
    alert = _make_alert(host="safe-host", event_snapshot={"src": {"ip": "7.7.7.7"}})
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="ip", value="7.7.7.7")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip" and "7.7.7.7" in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None
    assert result["matched"][0]["value"] == "7.7.7.7"


@pytest.mark.asyncio
async def test_lookup_threat_intel_ocsf_dst_ip():
    """Matches when OCSF dst.ip nested field is a known IP IOC."""
    mgr = _make_manager()
    alert = _make_alert(host="safe-host", event_snapshot={"dst": {"ip": "8.8.8.8"}})
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="ip", value="8.8.8.8")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip" and "8.8.8.8" in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None


@pytest.mark.asyncio
async def test_lookup_threat_intel_ocsf_process_file_hash_md5():
    """Matches when OCSF process.file.hash_md5 nested field is a known IOC."""
    mgr = _make_manager()
    md5 = "aabbccdd00112233aabbccdd00112233"
    alert = _make_alert(
        host="safe-host",
        event_snapshot={"process": {"file": {"hash_md5": md5}}},
    )
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="hash_md5", value=md5)

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "hash_md5" and md5 in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None
    assert result["matched"][0]["ioc_type"] == "hash_md5"


@pytest.mark.asyncio
async def test_lookup_threat_intel_ocsf_process_file_hash_sha256():
    """Matches when OCSF process.file.hash_sha256 nested field is a known IOC."""
    mgr = _make_manager()
    sha256 = "f" * 64
    alert = _make_alert(
        host="safe-host",
        event_snapshot={"process": {"file": {"hash_sha256": sha256}}},
    )
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="hash_sha256", value=sha256)

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "hash_sha256" and sha256 in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None


# ---------------------------------------------------------------------------
# _lookup_threat_intel() — inactive IOC filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_threat_intel_skips_inactive_ioc():
    """Inactive IOCs (is_active=False) are excluded from the result."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")
    ctx = _make_session_ctx()
    inactive_ioc = _make_ioc(ioc_type="ip", value="1.2.3.4", is_active=False)

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip":
            return [inactive_ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()) as mock_inc,
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is None
    mock_inc.assert_not_called()


# ---------------------------------------------------------------------------
# _lookup_threat_intel() — hit count increment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_threat_intel_increments_hit_count():
    """increment_hit is called for each matched active IOC."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_id=42, ioc_type="ip", value="1.2.3.4")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip" and "1.2.3.4" in values:
            return [ioc]
        return []

    mock_inc = AsyncMock()
    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=mock_inc),
    ):
        await mgr._lookup_threat_intel(alert)

    # increment_hit called with ioc.id = 42
    mock_inc.assert_awaited_once()
    call_args = mock_inc.call_args
    assert call_args.args[1] == 42


@pytest.mark.asyncio
async def test_lookup_threat_intel_commits_when_matches_found():
    """Session.commit() is called when at least one IOC matches."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")
    mock_session = AsyncMock()
    ctx = _make_session_ctx(mock_session)
    ioc = _make_ioc(ioc_type="ip", value="1.2.3.4")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip" and "1.2.3.4" in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        await mgr._lookup_threat_intel(alert)

    mock_session.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# _lookup_threat_intel() — result structure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_threat_intel_result_has_required_keys():
    """Result dict contains matched, ioc_count, and highest_severity."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")
    ctx = _make_session_ctx()
    ioc = _make_ioc(ioc_type="ip", value="1.2.3.4", severity="medium")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip" and "1.2.3.4" in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert "matched" in result
    assert "ioc_count" in result
    assert "highest_severity" in result


@pytest.mark.asyncio
async def test_lookup_threat_intel_matched_entry_has_all_fields():
    """Each entry in matched list has all required IOC fields."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")
    ctx = _make_session_ctx()
    ioc = _make_ioc(
        ioc_id=99, ioc_type="ip", value="1.2.3.4", severity="high",
        confidence=90, source="opencti", tags=["apt29"], description="APT29 C2",
    )

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip" and "1.2.3.4" in values:
            return [ioc]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    entry = result["matched"][0]
    assert entry["ioc_id"] == 99
    assert entry["ioc_type"] == "ip"
    assert entry["value"] == "1.2.3.4"
    assert entry["severity"] == "high"
    assert entry["confidence"] == 90
    assert entry["source"] == "opencti"
    assert entry["tags"] == ["apt29"]
    assert entry["description"] == "APT29 C2"


@pytest.mark.asyncio
async def test_lookup_threat_intel_ioc_count_correct():
    """ioc_count equals the number of matched active IOCs."""
    mgr = _make_manager()
    alert = _make_alert(
        host="1.2.3.4",
        event_snapshot={"src_ip": "5.5.5.5"},
    )
    ctx = _make_session_ctx()
    ioc1 = _make_ioc(ioc_id=1, ioc_type="ip", value="1.2.3.4")
    ioc2 = _make_ioc(ioc_id=2, ioc_type="ip", value="5.5.5.5")

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip":
            return [i for i in [ioc1, ioc2] if i.value in values]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None
    assert result["ioc_count"] == 2


# ---------------------------------------------------------------------------
# _lookup_threat_intel() — highest_severity ordering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("severities,expected", [
    (["low"],               "low"),
    (["medium"],            "medium"),
    (["high"],              "high"),
    (["critical"],          "critical"),
    (["low", "high"],       "high"),
    (["medium", "critical"],"critical"),
    (["low", "medium", "high", "critical"], "critical"),
])
@pytest.mark.asyncio
async def test_lookup_threat_intel_highest_severity_ordering(severities, expected):
    """highest_severity picks the worst severity across all matched IOCs."""
    mgr = _make_manager()
    alert = _make_alert(host="safe-host", event_snapshot={
        "src_ip": f"10.0.0.{i + 1}" for i, _ in enumerate(severities)
    })
    ctx = _make_session_ctx()

    # Build one IOC per severity, each with a distinct IP that we'll inject
    # via src_ip in the snapshot.
    iocs_by_ip = {
        f"10.0.0.{i + 1}": _make_ioc(
            ioc_id=i, ioc_type="ip", value=f"10.0.0.{i + 1}", severity=sev
        )
        for i, sev in enumerate(severities)
    }

    async def _mock_bulk_lookup(session, ioc_type: str, values: list[str]):
        if ioc_type == "ip":
            return [iocs_by_ip[v] for v in values if v in iocs_by_ip]
        return []

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", new=_mock_bulk_lookup),
        patch("app.repositories.ioc_repo.IOCRepo.increment_hit", new=AsyncMock()),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is not None
    assert result["highest_severity"] == expected


# ---------------------------------------------------------------------------
# _lookup_threat_intel() — fail-open behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_lookup_threat_intel_fail_open_on_db_error():
    """Returns None (fail-open) when AsyncSessionLocal raises."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")

    with patch("app.core.database.AsyncSessionLocal", side_effect=Exception("DB down")):
        result = await mgr._lookup_threat_intel(alert)

    assert result is None


@pytest.mark.asyncio
async def test_lookup_threat_intel_fail_open_on_ioc_repo_error():
    """Returns None (fail-open) when IOCRepo.bulk_lookup raises."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")
    ctx = _make_session_ctx()

    with (
        patch("app.core.database.AsyncSessionLocal", return_value=ctx),
        patch("app.repositories.ioc_repo.IOCRepo.bulk_lookup", side_effect=Exception("repo error")),
    ):
        result = await mgr._lookup_threat_intel(alert)

    assert result is None


# ---------------------------------------------------------------------------
# _enrich() integration
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enrich_threat_intel_field_populated_when_match():
    """_enrich() embeds threat_intel dict when _lookup_threat_intel returns a match."""
    mgr = _make_manager()
    alert = _make_alert(host="1.2.3.4")
    ti_data = {
        "matched": [{"ioc_id": 1, "ioc_type": "ip", "value": "1.2.3.4",
                     "severity": "high", "confidence": 80, "source": "opencti",
                     "tags": [], "description": None}],
        "ioc_count": 1,
        "highest_severity": "high",
    }

    with (
        patch.object(AlertManager, "_lookup_threat_intel", new=AsyncMock(return_value=ti_data)),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
    ):
        enriched = await mgr._enrich(alert)

    assert enriched["threat_intel"] == ti_data


@pytest.mark.asyncio
async def test_enrich_threat_intel_none_when_no_match():
    """_enrich() has threat_intel=None when _lookup_threat_intel returns None."""
    mgr = _make_manager()
    alert = _make_alert(host="safe-host")

    with (
        patch.object(AlertManager, "_lookup_threat_intel", new=AsyncMock(return_value=None)),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
    ):
        enriched = await mgr._enrich(alert)

    assert enriched["threat_intel"] is None


# ---------------------------------------------------------------------------
# process() end-to-end
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_threat_intel_in_published_payload():
    """Published enriched alert contains threat_intel when an IOC matches."""
    mgr = _make_manager()
    ti_data = {
        "matched": [{"ioc_id": 7, "ioc_type": "ip", "value": "192.168.1.10",
                     "severity": "critical", "confidence": 95, "source": "opencti",
                     "tags": ["ransomware"], "description": "Ransomware C2"}],
        "ioc_count": 1,
        "highest_severity": "critical",
    }
    published: list[dict] = []

    async def _capture(_topic, msg):
        published.append(msg)

    with (
        patch.object(AlertManager, "_lookup_threat_intel", new=AsyncMock(return_value=ti_data)),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_persist_to_db", new=AsyncMock()),
        patch.object(AlertManager, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(mgr._queue, "publish", side_effect=_capture),
    ):
        await mgr.process(_ALERT_DICT)

    assert len(published) == 1
    assert published[0]["threat_intel"] == ti_data


@pytest.mark.asyncio
async def test_process_threat_intel_none_in_published_payload():
    """Published enriched alert has threat_intel=None when no IOC matches."""
    mgr = _make_manager()
    published: list[dict] = []

    async def _capture(_topic, msg):
        published.append(msg)

    with (
        patch.object(AlertManager, "_lookup_threat_intel", new=AsyncMock(return_value=None)),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_persist_to_db", new=AsyncMock()),
        patch.object(AlertManager, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(mgr._queue, "publish", side_effect=_capture),
    ):
        await mgr.process(_ALERT_DICT)

    assert len(published) == 1
    assert published[0]["threat_intel"] is None


@pytest.mark.asyncio
async def test_process_threat_intel_lookup_failure_does_not_block_pipeline():
    """Even when _lookup_threat_intel fails (returns None), process() publishes the alert."""
    mgr = _make_manager()
    published: list[dict] = []

    async def _capture(_topic, msg):
        published.append(msg)

    with (
        patch.object(AlertManager, "_lookup_threat_intel", new=AsyncMock(return_value=None)),
        patch.object(AlertManager, "_get_recurrence_count", new=AsyncMock(return_value=0)),
        patch.object(AlertManager, "_persist_to_db", new=AsyncMock()),
        patch.object(AlertManager, "_is_suppressed", new=AsyncMock(return_value=False)),
        patch.object(mgr._queue, "publish", side_effect=_capture),
    ):
        await mgr.process(_ALERT_DICT)

    assert len(published) == 1
