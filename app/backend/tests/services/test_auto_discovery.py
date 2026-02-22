"""Tests for Feature 30.5 — Asset auto-discovery.

Coverage:
  - AssetDiscovery.is_internal_ip(): RFC 1918 IPs → True, public IPs → False,
    invalid strings → False.
  - AssetDiscovery._is_rate_limited(): Valkey SET NX behavior — first call
    returns True (not limited), subsequent calls return None (limited).
    Valkey error → fail-open (not limited).
  - AssetDiscovery.process_event(): disabled via settings → no-op.
  - AssetDiscovery.process_event() with Wazuh event: upserts by dst hostname.
  - AssetDiscovery.process_event() with Zeek conn event: upserts src and dst
    internal IPs; external IPs skipped.
  - AssetDiscovery.process_event() with Suricata event: upserts src and dst
    internal IPs.
  - AssetDiscovery.process_event() with MxGuard event: upserts by dst hostname.
  - Rate limiting: second process_event call for same hostname is skipped.
  - External-only event produces no upsert.
  - Unknown source produces no upsert.
  - Duplicate src/dst endpoints (same IP) produce a single upsert.
  - NormalizerPipeline integration: discovery.process_event called after
    normalization for Wazuh, Zeek, Suricata handlers.
  - NormalizerPipeline without discovery: pipeline works without discovery
    (backward compat).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.auto_discovery import AssetDiscovery, _RATE_LIMIT_PREFIX
from app.services.normalizers.ocsf import Endpoint, OCSFCategory, OCSFClass, OCSFEvent
from app.services.normalizers.pipeline import NormalizerPipeline
from app.pipeline.queue import InMemoryQueue, Topic


# ── OCSFEvent builders ────────────────────────────────────────────────────────


def _wazuh_event(
    *,
    hostname: str = "WIN-DC01",
    ip: str = "192.168.1.10",
    os_name: str | None = "Windows Server 2022",
) -> OCSFEvent:
    return OCSFEvent(
        class_uid=OCSFClass.SECURITY_FINDING,
        class_name="Security Finding",
        category_uid=OCSFCategory.FINDINGS,
        metadata_product="Wazuh",
        dst_endpoint=Endpoint(hostname=hostname, ip=ip, os_name=os_name),
    )


def _zeek_conn_event(
    *,
    src_ip: str = "10.0.0.5",
    dst_ip: str = "203.0.113.1",
) -> OCSFEvent:
    return OCSFEvent(
        class_uid=OCSFClass.NETWORK_ACTIVITY,
        class_name="Network Activity",
        category_uid=OCSFCategory.NETWORK,
        metadata_product="Zeek",
        src_endpoint=Endpoint(ip=src_ip),
        dst_endpoint=Endpoint(ip=dst_ip),
    )


def _suricata_event(
    *,
    src_ip: str = "192.168.1.200",
    dst_ip: str = "10.0.0.5",
) -> OCSFEvent:
    return OCSFEvent(
        class_uid=OCSFClass.SECURITY_FINDING,
        class_name="Security Finding",
        category_uid=OCSFCategory.FINDINGS,
        metadata_product="Suricata",
        src_endpoint=Endpoint(ip=src_ip),
        dst_endpoint=Endpoint(ip=dst_ip),
    )


def _mxguard_event(
    *,
    hostname: str = "linux-server-01",
    ip: str = "10.10.0.50",
    os_name: str | None = "Ubuntu 22.04",
) -> OCSFEvent:
    return OCSFEvent(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        class_name="Process Activity",
        category_uid=OCSFCategory.SYSTEM_ACTIVITY,
        metadata_product="MxGuard",
        dst_endpoint=Endpoint(hostname=hostname, ip=ip, os_name=os_name),
    )


# ── Fixture: AssetDiscovery with mocked Valkey ────────────────────────────────


def _make_discovery(*, valkey_set_return: Any = True) -> tuple[AssetDiscovery, MagicMock]:
    """Return (discovery, mock_valkey) with Valkey SET mocked."""
    mock_valkey = MagicMock()
    mock_valkey.set = AsyncMock(return_value=valkey_set_return)
    discovery = AssetDiscovery(mock_valkey)
    return discovery, mock_valkey


def _mock_session_ctx():
    """Return a mock async context manager that yields a mock AsyncSession."""
    mock_session = AsyncMock()
    mock_session.commit = AsyncMock()
    ctx = MagicMock()
    ctx.__aenter__ = AsyncMock(return_value=mock_session)
    ctx.__aexit__ = AsyncMock(return_value=False)
    return ctx, mock_session


# ── TestIsInternalIp ──────────────────────────────────────────────────────────


class TestIsInternalIp:
    """AssetDiscovery.is_internal_ip() covers RFC 1918 ranges."""

    def test_10_x_x_x_is_internal(self) -> None:
        discovery, _ = _make_discovery()
        assert discovery.is_internal_ip("10.0.0.1") is True

    def test_10_255_255_255_is_internal(self) -> None:
        discovery, _ = _make_discovery()
        assert discovery.is_internal_ip("10.255.255.255") is True

    def test_172_16_x_x_is_internal(self) -> None:
        discovery, _ = _make_discovery()
        assert discovery.is_internal_ip("172.16.0.1") is True

    def test_172_31_255_255_is_internal(self) -> None:
        discovery, _ = _make_discovery()
        assert discovery.is_internal_ip("172.31.255.255") is True

    def test_172_32_x_x_is_not_internal(self) -> None:
        """172.32.0.0 is outside 172.16.0.0/12."""
        discovery, _ = _make_discovery()
        assert discovery.is_internal_ip("172.32.0.1") is False

    def test_192_168_x_x_is_internal(self) -> None:
        discovery, _ = _make_discovery()
        assert discovery.is_internal_ip("192.168.1.10") is True

    def test_public_ip_is_not_internal(self) -> None:
        discovery, _ = _make_discovery()
        assert discovery.is_internal_ip("8.8.8.8") is False

    def test_loopback_is_not_internal(self) -> None:
        """127.0.0.1 is not in RFC1918 ranges."""
        discovery, _ = _make_discovery()
        assert discovery.is_internal_ip("127.0.0.1") is False

    def test_invalid_string_returns_false(self) -> None:
        discovery, _ = _make_discovery()
        assert discovery.is_internal_ip("not-an-ip") is False

    def test_empty_string_returns_false(self) -> None:
        discovery, _ = _make_discovery()
        assert discovery.is_internal_ip("") is False


# ── TestIsRateLimited ─────────────────────────────────────────────────────────


class TestIsRateLimited:

    async def test_first_call_returns_not_limited(self) -> None:
        """Valkey SET returns True (key newly set) → not rate-limited."""
        discovery, mock_valkey = _make_discovery(valkey_set_return=True)
        result = await discovery._is_rate_limited("host-a")
        assert result is False

    async def test_second_call_returns_limited(self) -> None:
        """Valkey SET returns None (key exists) → rate-limited."""
        discovery, mock_valkey = _make_discovery(valkey_set_return=None)
        result = await discovery._is_rate_limited("host-a")
        assert result is True

    async def test_valkey_key_uses_prefix(self) -> None:
        discovery, mock_valkey = _make_discovery()
        await discovery._is_rate_limited("myhost")
        called_key = mock_valkey.set.call_args.args[0]
        assert called_key == f"{_RATE_LIMIT_PREFIX}myhost"

    async def test_valkey_key_uses_nx_and_ex(self) -> None:
        """SET must be called with NX=True and EX=300."""
        discovery, mock_valkey = _make_discovery()
        await discovery._is_rate_limited("myhost")
        kwargs = mock_valkey.set.call_args.kwargs
        assert kwargs.get("nx") is True
        assert kwargs.get("ex") == 300

    async def test_valkey_error_is_fail_open(self) -> None:
        """Valkey exception → fail-open (not rate-limited, allow upsert)."""
        mock_valkey = MagicMock()
        mock_valkey.set = AsyncMock(side_effect=ConnectionError("redis down"))
        discovery = AssetDiscovery(mock_valkey)
        result = await discovery._is_rate_limited("host-a")
        assert result is False


# ── TestExtractCandidates ─────────────────────────────────────────────────────


class TestExtractCandidates:

    def test_wazuh_extracts_dst_hostname_and_internal_ip(self) -> None:
        discovery, _ = _make_discovery()
        event = _wazuh_event(hostname="WIN-DC01", ip="192.168.1.10", os_name="Windows")
        candidates = discovery._extract_candidates(event, "wazuh")
        assert len(candidates) == 1
        hostname, ips, os_name = candidates[0]
        assert hostname == "WIN-DC01"
        assert "192.168.1.10" in ips
        assert os_name == "Windows"

    def test_wazuh_excludes_external_ip(self) -> None:
        """External IP on Wazuh agent → empty ip_addresses, hostname still captured."""
        discovery, _ = _make_discovery()
        event = _wazuh_event(hostname="WIN-DC01", ip="8.8.8.8")
        candidates = discovery._extract_candidates(event, "wazuh")
        assert len(candidates) == 1
        _, ips, _ = candidates[0]
        assert ips == []

    def test_wazuh_no_hostname_produces_no_candidate(self) -> None:
        """Wazuh events without a hostname in dst_endpoint are skipped."""
        discovery, _ = _make_discovery()
        event = OCSFEvent(
            class_uid=OCSFClass.SECURITY_FINDING,
            class_name="Security Finding",
            category_uid=OCSFCategory.FINDINGS,
            metadata_product="Wazuh",
            dst_endpoint=Endpoint(ip="192.168.1.10"),
        )
        candidates = discovery._extract_candidates(event, "wazuh")
        assert candidates == []

    def test_zeek_extracts_internal_src_ip(self) -> None:
        discovery, _ = _make_discovery()
        event = _zeek_conn_event(src_ip="10.0.0.5", dst_ip="203.0.113.1")
        candidates = discovery._extract_candidates(event, "zeek")
        hostnames = [c[0] for c in candidates]
        assert "10.0.0.5" in hostnames

    def test_zeek_extracts_both_internal_ips(self) -> None:
        """Both src and dst are internal → two candidates."""
        discovery, _ = _make_discovery()
        event = _zeek_conn_event(src_ip="10.0.0.5", dst_ip="192.168.1.10")
        candidates = discovery._extract_candidates(event, "zeek")
        assert len(candidates) == 2

    def test_zeek_skips_external_ip(self) -> None:
        """External dst IP → only src (internal) is returned."""
        discovery, _ = _make_discovery()
        event = _zeek_conn_event(src_ip="10.0.0.5", dst_ip="8.8.8.8")
        candidates = discovery._extract_candidates(event, "zeek")
        assert len(candidates) == 1
        assert candidates[0][1] == ["10.0.0.5"]

    def test_zeek_both_external_produces_no_candidates(self) -> None:
        discovery, _ = _make_discovery()
        event = _zeek_conn_event(src_ip="1.2.3.4", dst_ip="5.6.7.8")
        candidates = discovery._extract_candidates(event, "zeek")
        assert candidates == []

    def test_zeek_uses_ip_as_hostname_when_no_hostname(self) -> None:
        """Zeek endpoints lack hostnames → IP used as the upsert key."""
        discovery, _ = _make_discovery()
        event = _zeek_conn_event(src_ip="10.0.0.5", dst_ip="203.0.113.1")
        candidates = discovery._extract_candidates(event, "zeek")
        assert len(candidates) == 1
        assert candidates[0][0] == "10.0.0.5"

    def test_suricata_extracts_both_internal_ips(self) -> None:
        discovery, _ = _make_discovery()
        event = _suricata_event(src_ip="192.168.1.200", dst_ip="10.0.0.5")
        candidates = discovery._extract_candidates(event, "suricata")
        assert len(candidates) == 2

    def test_suricata_skips_external_ip(self) -> None:
        discovery, _ = _make_discovery()
        event = _suricata_event(src_ip="8.8.8.8", dst_ip="10.0.0.5")
        candidates = discovery._extract_candidates(event, "suricata")
        assert len(candidates) == 1

    def test_mxguard_extracts_dst_hostname(self) -> None:
        discovery, _ = _make_discovery()
        event = _mxguard_event(hostname="linux-server-01", ip="10.10.0.50", os_name="Ubuntu 22.04")
        candidates = discovery._extract_candidates(event, "mxguard")
        assert len(candidates) == 1
        hostname, ips, os_name = candidates[0]
        assert hostname == "linux-server-01"
        assert "10.10.0.50" in ips
        assert os_name == "Ubuntu 22.04"

    def test_unknown_source_returns_empty(self) -> None:
        discovery, _ = _make_discovery()
        event = _wazuh_event()
        candidates = discovery._extract_candidates(event, "unknown_source")
        assert candidates == []


# ── TestProcessEvent ──────────────────────────────────────────────────────────


class TestProcessEvent:

    async def test_disabled_setting_is_noop(self) -> None:
        """When asset_auto_discovery=False, no DB calls are made."""
        discovery, mock_valkey = _make_discovery()
        event = _wazuh_event()

        with patch("app.services.auto_discovery.settings") as mock_settings:
            mock_settings.asset_auto_discovery = False
            with patch("app.core.database.AsyncSessionLocal") as mock_sl:
                await discovery.process_event(event, "wazuh")
                mock_sl.assert_not_called()

    async def test_wazuh_event_triggers_upsert(self) -> None:
        """Wazuh event with internal IP → AssetRepo.upsert_by_hostname called."""
        discovery, mock_valkey = _make_discovery(valkey_set_return=True)
        event = _wazuh_event(hostname="WIN-DC01", ip="192.168.1.10")

        ctx, mock_session = _mock_session_ctx()

        with patch("app.services.auto_discovery.settings") as mock_settings:
            mock_settings.asset_auto_discovery = True
            mock_settings.asset_internal_networks = [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
            ]
            # Re-parse networks with the patched settings
            discovery._networks = [
                __import__("ipaddress").ip_network(c, strict=False)
                for c in mock_settings.asset_internal_networks
            ]
            with patch("app.services.auto_discovery.AsyncSessionLocal", return_value=ctx):
                with patch("app.services.auto_discovery.AssetRepo") as mock_repo:
                    mock_repo.upsert_by_hostname = AsyncMock()
                    await discovery.process_event(event, "wazuh")
                    mock_repo.upsert_by_hostname.assert_awaited_once()
                    call_kwargs = mock_repo.upsert_by_hostname.call_args
                    assert call_kwargs.args[1] == "WIN-DC01"  # hostname

    async def test_wazuh_event_passes_ip_addresses(self) -> None:
        """Upsert kwargs must include ip_addresses for internal IPs."""
        discovery, _ = _make_discovery(valkey_set_return=True)
        event = _wazuh_event(hostname="WIN-DC01", ip="192.168.1.10")

        ctx, _ = _mock_session_ctx()
        with patch("app.services.auto_discovery.settings") as mock_settings:
            mock_settings.asset_auto_discovery = True
            mock_settings.asset_internal_networks = [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
            ]
            discovery._networks = [
                __import__("ipaddress").ip_network(c, strict=False)
                for c in mock_settings.asset_internal_networks
            ]
            with patch("app.services.auto_discovery.AsyncSessionLocal", return_value=ctx):
                with patch("app.services.auto_discovery.AssetRepo") as mock_repo:
                    mock_repo.upsert_by_hostname = AsyncMock()
                    await discovery.process_event(event, "wazuh")
                    kwargs = mock_repo.upsert_by_hostname.call_args.kwargs
                    assert "ip_addresses" in kwargs
                    assert "192.168.1.10" in kwargs["ip_addresses"]

    async def test_wazuh_event_passes_os_when_available(self) -> None:
        discovery, _ = _make_discovery(valkey_set_return=True)
        event = _wazuh_event(hostname="WIN-DC01", ip="192.168.1.10", os_name="Windows Server 2022")

        ctx, _ = _mock_session_ctx()
        with patch("app.services.auto_discovery.settings") as mock_settings:
            mock_settings.asset_auto_discovery = True
            mock_settings.asset_internal_networks = [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
            ]
            discovery._networks = [
                __import__("ipaddress").ip_network(c, strict=False)
                for c in mock_settings.asset_internal_networks
            ]
            with patch("app.services.auto_discovery.AsyncSessionLocal", return_value=ctx):
                with patch("app.services.auto_discovery.AssetRepo") as mock_repo:
                    mock_repo.upsert_by_hostname = AsyncMock()
                    await discovery.process_event(event, "wazuh")
                    kwargs = mock_repo.upsert_by_hostname.call_args.kwargs
                    assert kwargs.get("os") == "Windows Server 2022"

    async def test_wazuh_event_sets_last_seen_at(self) -> None:
        discovery, _ = _make_discovery(valkey_set_return=True)
        event = _wazuh_event(hostname="WIN-DC01", ip="192.168.1.10")

        ctx, _ = _mock_session_ctx()
        with patch("app.services.auto_discovery.settings") as mock_settings:
            mock_settings.asset_auto_discovery = True
            mock_settings.asset_internal_networks = [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
            ]
            discovery._networks = [
                __import__("ipaddress").ip_network(c, strict=False)
                for c in mock_settings.asset_internal_networks
            ]
            with patch("app.services.auto_discovery.AsyncSessionLocal", return_value=ctx):
                with patch("app.services.auto_discovery.AssetRepo") as mock_repo:
                    mock_repo.upsert_by_hostname = AsyncMock()
                    await discovery.process_event(event, "wazuh")
                    kwargs = mock_repo.upsert_by_hostname.call_args.kwargs
                    assert "last_seen_at" in kwargs
                    assert isinstance(kwargs["last_seen_at"], datetime)

    async def test_rate_limited_hostname_skips_upsert(self) -> None:
        """Second process_event call within rate window must not upsert."""
        discovery, mock_valkey = _make_discovery()
        # First call → set key (not limited); second call → key exists (limited)
        mock_valkey.set = AsyncMock(side_effect=[True, None])
        event = _wazuh_event(hostname="WIN-DC01", ip="192.168.1.10")

        ctx, _ = _mock_session_ctx()
        with patch("app.services.auto_discovery.settings") as mock_settings:
            mock_settings.asset_auto_discovery = True
            mock_settings.asset_internal_networks = [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
            ]
            discovery._networks = [
                __import__("ipaddress").ip_network(c, strict=False)
                for c in mock_settings.asset_internal_networks
            ]
            with patch("app.services.auto_discovery.AsyncSessionLocal", return_value=ctx):
                with patch("app.services.auto_discovery.AssetRepo") as mock_repo:
                    mock_repo.upsert_by_hostname = AsyncMock()
                    # First call — should upsert
                    await discovery.process_event(event, "wazuh")
                    # Second call — rate-limited, no upsert
                    await discovery.process_event(event, "wazuh")
                    assert mock_repo.upsert_by_hostname.await_count == 1

    async def test_external_only_event_produces_no_upsert(self) -> None:
        """Zeek event with only external IPs → no upsert."""
        discovery, _ = _make_discovery(valkey_set_return=True)
        event = _zeek_conn_event(src_ip="1.2.3.4", dst_ip="5.6.7.8")

        with patch("app.services.auto_discovery.settings") as mock_settings:
            mock_settings.asset_auto_discovery = True
            mock_settings.asset_internal_networks = [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
            ]
            discovery._networks = [
                __import__("ipaddress").ip_network(c, strict=False)
                for c in mock_settings.asset_internal_networks
            ]
            with patch("app.services.auto_discovery.AsyncSessionLocal") as mock_sl:
                await discovery.process_event(event, "zeek")
                mock_sl.assert_not_called()

    async def test_zeek_two_internal_ips_produce_two_upserts(self) -> None:
        """Both src and dst are internal → upsert called twice (one per IP)."""
        discovery, mock_valkey = _make_discovery(valkey_set_return=True)
        event = _zeek_conn_event(src_ip="10.0.0.5", dst_ip="192.168.1.10")

        ctx, _ = _mock_session_ctx()
        with patch("app.services.auto_discovery.settings") as mock_settings:
            mock_settings.asset_auto_discovery = True
            mock_settings.asset_internal_networks = [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
            ]
            discovery._networks = [
                __import__("ipaddress").ip_network(c, strict=False)
                for c in mock_settings.asset_internal_networks
            ]
            with patch("app.services.auto_discovery.AsyncSessionLocal", return_value=ctx):
                with patch("app.services.auto_discovery.AssetRepo") as mock_repo:
                    mock_repo.upsert_by_hostname = AsyncMock()
                    await discovery.process_event(event, "zeek")
                    assert mock_repo.upsert_by_hostname.await_count == 2

    async def test_duplicate_src_dst_ip_produces_single_upsert(self) -> None:
        """When src and dst are the same internal IP, deduplicate → one upsert."""
        discovery, _ = _make_discovery(valkey_set_return=True)
        # Craft event with identical src and dst IP
        event = OCSFEvent(
            class_uid=OCSFClass.NETWORK_ACTIVITY,
            class_name="Network Activity",
            category_uid=OCSFCategory.NETWORK,
            metadata_product="Zeek",
            src_endpoint=Endpoint(ip="10.0.0.5"),
            dst_endpoint=Endpoint(ip="10.0.0.5"),
        )
        ctx, _ = _mock_session_ctx()
        with patch("app.services.auto_discovery.settings") as mock_settings:
            mock_settings.asset_auto_discovery = True
            mock_settings.asset_internal_networks = [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
            ]
            discovery._networks = [
                __import__("ipaddress").ip_network(c, strict=False)
                for c in mock_settings.asset_internal_networks
            ]
            with patch("app.services.auto_discovery.AsyncSessionLocal", return_value=ctx):
                with patch("app.services.auto_discovery.AssetRepo") as mock_repo:
                    mock_repo.upsert_by_hostname = AsyncMock()
                    await discovery.process_event(event, "zeek")
                    # Same hostname ("10.0.0.5") → deduplicated → single upsert
                    assert mock_repo.upsert_by_hostname.await_count == 1

    async def test_process_event_exception_does_not_propagate(self) -> None:
        """Any unhandled exception inside _do_process must be caught."""
        discovery, _ = _make_discovery(valkey_set_return=True)
        event = _wazuh_event()

        with patch.object(
            discovery, "_do_process", side_effect=RuntimeError("boom")
        ):
            # Must not raise
            await discovery.process_event(event, "wazuh")

    async def test_valkey_error_in_rate_limit_does_not_block_upsert(self) -> None:
        """Valkey down → fail-open → upsert still happens."""
        mock_valkey = MagicMock()
        mock_valkey.set = AsyncMock(side_effect=ConnectionError("redis down"))
        discovery = AssetDiscovery(mock_valkey)
        event = _wazuh_event(hostname="WIN-DC01", ip="192.168.1.10")

        ctx, _ = _mock_session_ctx()
        with patch("app.services.auto_discovery.settings") as mock_settings:
            mock_settings.asset_auto_discovery = True
            mock_settings.asset_internal_networks = [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
            ]
            discovery._networks = [
                __import__("ipaddress").ip_network(c, strict=False)
                for c in mock_settings.asset_internal_networks
            ]
            with patch("app.services.auto_discovery.AsyncSessionLocal", return_value=ctx):
                with patch("app.services.auto_discovery.AssetRepo") as mock_repo:
                    mock_repo.upsert_by_hostname = AsyncMock()
                    await discovery.process_event(event, "wazuh")
                    # Fail-open: upsert still called
                    mock_repo.upsert_by_hostname.assert_awaited_once()

    async def test_upsert_includes_asset_type_server(self) -> None:
        """Auto-discovered assets must have asset_type='server'."""
        discovery, _ = _make_discovery(valkey_set_return=True)
        event = _wazuh_event(hostname="WIN-DC01", ip="192.168.1.10")

        ctx, _ = _mock_session_ctx()
        with patch("app.services.auto_discovery.settings") as mock_settings:
            mock_settings.asset_auto_discovery = True
            mock_settings.asset_internal_networks = [
                "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"
            ]
            discovery._networks = [
                __import__("ipaddress").ip_network(c, strict=False)
                for c in mock_settings.asset_internal_networks
            ]
            with patch("app.services.auto_discovery.AsyncSessionLocal", return_value=ctx):
                with patch("app.services.auto_discovery.AssetRepo") as mock_repo:
                    mock_repo.upsert_by_hostname = AsyncMock()
                    await discovery.process_event(event, "wazuh")
                    kwargs = mock_repo.upsert_by_hostname.call_args.kwargs
                    assert kwargs.get("asset_type") == "server"


# ── TestNormalizerPipelineDiscoveryIntegration ────────────────────────────────


class TestNormalizerPipelineDiscoveryIntegration:
    """NormalizerPipeline calls discovery.process_event after each normalize."""

    def _make_pipeline_with_mock_discovery(self) -> tuple[NormalizerPipeline, MagicMock]:
        q = MagicMock()
        q.publish = AsyncMock()
        q.subscribe = AsyncMock()
        mock_discovery = MagicMock()
        mock_discovery.process_event = AsyncMock()
        pipeline = NormalizerPipeline(q, discovery=mock_discovery)
        return pipeline, mock_discovery

    async def test_wazuh_handler_calls_discovery(self) -> None:
        pipeline, mock_discovery = self._make_pipeline_with_mock_discovery()
        raw = {
            "id": "w001",
            "timestamp": "2026-02-22T10:00:00.000+0000",
            "agent": {"id": "001", "name": "win-host", "ip": "10.0.0.10"},
            "rule": {"id": "100200", "level": 10, "description": "Test"},
            "data": {},
        }
        await pipeline._handle_wazuh(raw)
        mock_discovery.process_event.assert_awaited_once()
        source = mock_discovery.process_event.call_args.args[1]
        assert source == "wazuh"

    async def test_zeek_handler_calls_discovery(self) -> None:
        pipeline, mock_discovery = self._make_pipeline_with_mock_discovery()
        raw = {
            "_log_type": "conn",
            "ts": 1740218400.0,
            "uid": "Ctest001",
            "id.orig_h": "10.0.0.5",
            "id.orig_p": 55001,
            "id.resp_h": "203.0.113.1",
            "id.resp_p": 80,
            "proto": "tcp",
            "conn_state": "SF",
        }
        await pipeline._handle_zeek(raw)
        mock_discovery.process_event.assert_awaited_once()
        source = mock_discovery.process_event.call_args.args[1]
        assert source == "zeek"

    async def test_suricata_handler_calls_discovery(self) -> None:
        pipeline, mock_discovery = self._make_pipeline_with_mock_discovery()
        raw = {
            "timestamp": "2026-02-22T10:30:00.000000+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.200",
            "src_port": 4444,
            "dest_ip": "10.0.0.5",
            "dest_port": 443,
            "proto": "TCP",
            "flow_id": 123,
            "alert": {
                "action": "allowed",
                "signature_id": 2030358,
                "signature": "ET MALWARE Test",
                "category": "Trojan",
                "severity": 1,
            },
        }
        await pipeline._handle_suricata(raw)
        mock_discovery.process_event.assert_awaited_once()
        source = mock_discovery.process_event.call_args.args[1]
        assert source == "suricata"

    async def test_pipeline_without_discovery_still_publishes(self) -> None:
        """Backward compat: NormalizerPipeline(q) works without discovery."""
        q = MagicMock()
        q.publish = AsyncMock()
        pipeline = NormalizerPipeline(q)  # no discovery argument
        raw = {
            "id": "w001",
            "timestamp": "2026-02-22T10:00:00.000+0000",
            "agent": {"id": "001", "name": "win-host", "ip": "10.0.0.10"},
            "rule": {"id": "100200", "level": 10, "description": "Test"},
            "data": {},
        }
        # Must not raise
        await pipeline._handle_wazuh(raw)
        q.publish.assert_awaited_once()
        topic = q.publish.call_args.args[0]
        assert topic == Topic.NORMALIZED

    async def test_discovery_called_before_publish(self) -> None:
        """Discovery must be invoked before the event is published to NORMALIZED."""
        call_order: list[str] = []

        q = MagicMock()

        async def _record_publish(topic: str, msg: Any) -> None:
            call_order.append("publish")

        q.publish = AsyncMock(side_effect=_record_publish)
        q.subscribe = AsyncMock()

        mock_discovery = MagicMock()

        async def _record_discovery(event: Any, source: str) -> None:
            call_order.append("discovery")

        mock_discovery.process_event = AsyncMock(side_effect=_record_discovery)

        pipeline = NormalizerPipeline(q, discovery=mock_discovery)
        raw = {
            "id": "w001",
            "timestamp": "2026-02-22T10:00:00.000+0000",
            "agent": {"id": "001", "name": "win-host", "ip": "10.0.0.10"},
            "rule": {"id": "100200", "level": 10, "description": "Test"},
            "data": {},
        }
        await pipeline._handle_wazuh(raw)
        assert call_order == ["discovery", "publish"]

    async def test_normalizer_error_skips_discovery(self) -> None:
        """If normalizer raises, discovery must not be called."""
        q = MagicMock()
        q.publish = AsyncMock()
        mock_discovery = MagicMock()
        mock_discovery.process_event = AsyncMock()
        pipeline = NormalizerPipeline(q, discovery=mock_discovery)

        with patch.object(pipeline._wazuh, "normalize", side_effect=RuntimeError("fail")):
            await pipeline._handle_wazuh({})

        mock_discovery.process_event.assert_not_awaited()
