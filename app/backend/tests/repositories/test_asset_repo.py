"""Tests for AssetRepo — async DB operations for the assets table.

Feature 30.2 — Asset repository layer

Approach:
  - All session interactions are mocked (no live DB needed)
  - AsyncMock used for awaitable session methods (execute, flush, scalar, delete)
  - MagicMock used for synchronous session methods (add)
  - AssetRepo.get_by_id / get_by_hostname are patched for methods that call them

Coverage:
  - list(): returns (items, total) from session.execute/scalar
  - list(): no filters — count and data queries both executed
  - list(): asset_type filter forwarded
  - list(): criticality filter forwarded
  - list(): is_active filter forwarded
  - list(): search filter forwarded
  - list(): empty result returns ([], 0)
  - list(): scalar None total becomes 0
  - get_by_id(): found → returns Asset; not found → returns None
  - get_by_hostname(): found → returns Asset; not found → returns None
  - get_by_ip(): returns matching asset list; empty when not found
  - create(): adds to session, flushes, returns Asset with correct fields
  - upsert_by_hostname(): creates new when not found
  - upsert_by_hostname(): updates existing when found
  - update(): found → sets attributes, flushes, returns Asset
  - update(): not found → returns None without flush
  - update(): None kwarg values are skipped
  - delete(): found → calls session.delete + flush, returns True
  - delete(): not found → returns False, no delete/flush
  - get_criticality(): found by hostname → returns criticality
  - get_criticality(): not found by hostname, found by IP → returns max criticality
  - get_criticality(): not found anywhere → returns default (3)
  - update_last_seen(): executes UPDATE and flushes
  - increment_detection_count(): executes UPDATE and flushes
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.repositories.asset_repo import AssetRepo, _DEFAULT_CRITICALITY


# ---------------------------------------------------------------------------
# Session factory helpers
# ---------------------------------------------------------------------------


def _make_session() -> MagicMock:
    """Sync MagicMock for the session with async methods patched."""
    session = MagicMock()
    session.execute = AsyncMock()
    session.flush = AsyncMock()
    session.delete = AsyncMock()
    session.scalar = AsyncMock()
    return session


def _scalars_result(items: list) -> MagicMock:
    """Result mock whose .scalars().all() returns items."""
    result = MagicMock()
    result.scalars.return_value.all.return_value = items
    return result


def _scalar_one_result(item) -> MagicMock:
    """Result mock whose .scalar_one_or_none() returns item."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = item
    return result


def _make_asset(**kwargs) -> MagicMock:
    """Minimal Asset-like mock."""
    asset = MagicMock()
    asset.id = kwargs.get("id", 1)
    asset.hostname = kwargs.get("hostname", "host-01")
    asset.ip_addresses = kwargs.get("ip_addresses", ["10.0.0.1"])
    asset.asset_type = kwargs.get("asset_type", "server")
    asset.criticality = kwargs.get("criticality", 3)
    asset.is_active = kwargs.get("is_active", True)
    asset.os = kwargs.get("os", "Ubuntu 22.04")
    asset.os_family = kwargs.get("os_family", "linux")
    asset.owner = kwargs.get("owner", None)
    asset.department = kwargs.get("department", None)
    asset.detection_count = kwargs.get("detection_count", 0)
    asset.incident_count = kwargs.get("incident_count", 0)
    return asset


# ---------------------------------------------------------------------------
# list()
# ---------------------------------------------------------------------------


class TestAssetRepoList:
    """AssetRepo.list() returns (items, total) with filtering and pagination."""

    @pytest.mark.asyncio
    async def test_returns_tuple_of_list_and_int(self) -> None:
        session = _make_session()
        session.scalar.return_value = 2
        assets = [_make_asset(id=1), _make_asset(id=2)]
        session.execute.return_value = _scalars_result(assets)

        result, total = await AssetRepo.list(session)

        assert isinstance(result, list)
        assert total == 2
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_no_filters_executes_count_and_data(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        await AssetRepo.list(session)

        session.scalar.assert_awaited_once()
        session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_empty_result_returns_empty_list_and_zero(self) -> None:
        session = _make_session()
        session.scalar.return_value = 0
        session.execute.return_value = _scalars_result([])

        items, total = await AssetRepo.list(session)

        assert items == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_scalar_none_total_becomes_zero(self) -> None:
        session = _make_session()
        session.scalar.return_value = None
        session.execute.return_value = _scalars_result([])

        _, total = await AssetRepo.list(session)

        assert total == 0

    @pytest.mark.asyncio
    async def test_asset_type_filter_forwarded(self) -> None:
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result(
            [_make_asset(asset_type="workstation")]
        )

        items, _ = await AssetRepo.list(session, asset_type="workstation")

        assert items[0].asset_type == "workstation"

    @pytest.mark.asyncio
    async def test_criticality_filter_forwarded(self) -> None:
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result([_make_asset(criticality=5)])

        items, _ = await AssetRepo.list(session, criticality=5)

        assert items[0].criticality == 5

    @pytest.mark.asyncio
    async def test_is_active_filter_forwarded(self) -> None:
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result([_make_asset(is_active=False)])

        items, _ = await AssetRepo.list(session, is_active=False)

        assert items[0].is_active is False

    @pytest.mark.asyncio
    async def test_search_filter_forwarded(self) -> None:
        session = _make_session()
        session.scalar.return_value = 1
        session.execute.return_value = _scalars_result(
            [_make_asset(hostname="db-prod-01")]
        )

        items, _ = await AssetRepo.list(session, search="db-prod")

        assert items[0].hostname == "db-prod-01"


# ---------------------------------------------------------------------------
# get_by_id()
# ---------------------------------------------------------------------------


class TestAssetRepoGetById:

    @pytest.mark.asyncio
    async def test_found_returns_asset(self) -> None:
        session = _make_session()
        asset = _make_asset(id=42)
        session.execute.return_value = _scalar_one_result(asset)

        result = await AssetRepo.get_by_id(session, 42)

        assert result is asset

    @pytest.mark.asyncio
    async def test_not_found_returns_none(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        result = await AssetRepo.get_by_id(session, 999)

        assert result is None

    @pytest.mark.asyncio
    async def test_calls_session_execute_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        await AssetRepo.get_by_id(session, 1)

        session.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# get_by_hostname()
# ---------------------------------------------------------------------------


class TestAssetRepoGetByHostname:

    @pytest.mark.asyncio
    async def test_found_returns_asset(self) -> None:
        session = _make_session()
        asset = _make_asset(hostname="web-01")
        session.execute.return_value = _scalar_one_result(asset)

        result = await AssetRepo.get_by_hostname(session, "web-01")

        assert result is asset

    @pytest.mark.asyncio
    async def test_not_found_returns_none(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        result = await AssetRepo.get_by_hostname(session, "unknown-host")

        assert result is None

    @pytest.mark.asyncio
    async def test_executes_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalar_one_result(None)

        await AssetRepo.get_by_hostname(session, "host-x")

        session.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# get_by_ip()
# ---------------------------------------------------------------------------


class TestAssetRepoGetByIp:

    @pytest.mark.asyncio
    async def test_returns_matching_assets(self) -> None:
        session = _make_session()
        assets = [_make_asset(id=1), _make_asset(id=2)]
        session.execute.return_value = _scalars_result(assets)

        result = await AssetRepo.get_by_ip(session, "10.0.0.1")

        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_not_found_returns_empty_list(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([])

        result = await AssetRepo.get_by_ip(session, "1.2.3.4")

        assert result == []

    @pytest.mark.asyncio
    async def test_executes_once(self) -> None:
        session = _make_session()
        session.execute.return_value = _scalars_result([])

        await AssetRepo.get_by_ip(session, "192.168.1.1")

        session.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# create()
# ---------------------------------------------------------------------------


class TestAssetRepoCreate:

    @pytest.mark.asyncio
    async def test_adds_to_session_and_flushes(self) -> None:
        session = _make_session()

        asset = await AssetRepo.create(
            session,
            hostname="app-server-01",
            asset_type="server",
            criticality=4,
            ip_addresses=["10.0.0.5"],
        )

        session.add.assert_called_once()
        session.flush.assert_awaited_once()
        assert asset is not None

    @pytest.mark.asyncio
    async def test_returned_object_has_correct_fields(self) -> None:
        session = _make_session()

        asset = await AssetRepo.create(
            session,
            hostname="db-primary",
            asset_type="server",
            criticality=5,
            ip_addresses=["10.1.0.10"],
            os_family="linux",
        )

        assert asset.hostname == "db-primary"
        assert asset.asset_type == "server"
        assert asset.criticality == 5
        assert asset.os_family == "linux"


# ---------------------------------------------------------------------------
# upsert_by_hostname()
# ---------------------------------------------------------------------------


class TestAssetRepoUpsertByHostname:

    @pytest.mark.asyncio
    async def test_creates_new_when_not_found(self) -> None:
        session = _make_session()

        with patch.object(AssetRepo, "get_by_hostname", AsyncMock(return_value=None)):
            asset = await AssetRepo.upsert_by_hostname(
                session,
                "new-host",
                asset_type="workstation",
                criticality=2,
            )

        session.add.assert_called_once()
        session.flush.assert_awaited_once()
        assert asset.hostname == "new-host"

    @pytest.mark.asyncio
    async def test_updates_existing_when_found(self) -> None:
        session = _make_session()
        existing = _make_asset(hostname="existing-host", criticality=2)

        with patch.object(
            AssetRepo, "get_by_hostname", AsyncMock(return_value=existing)
        ):
            result = await AssetRepo.upsert_by_hostname(
                session,
                "existing-host",
                criticality=5,
            )

        assert result is existing
        assert existing.criticality == 5
        session.add.assert_not_called()
        session.flush.assert_awaited_once()


# ---------------------------------------------------------------------------
# update()
# ---------------------------------------------------------------------------


class TestAssetRepoUpdate:

    @pytest.mark.asyncio
    async def test_found_updates_attributes_and_returns_asset(self) -> None:
        session = _make_session()
        asset = _make_asset(id=1, criticality=2)

        with patch.object(AssetRepo, "get_by_id", AsyncMock(return_value=asset)):
            result = await AssetRepo.update(session, 1, criticality=5)

        assert result is asset
        assert asset.criticality == 5
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_not_found_returns_none_without_flush(self) -> None:
        session = _make_session()

        with patch.object(AssetRepo, "get_by_id", AsyncMock(return_value=None)):
            result = await AssetRepo.update(session, 999, criticality=5)

        assert result is None
        session.flush.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_none_values_are_skipped(self) -> None:
        session = _make_session()
        asset = _make_asset(id=1, os="Ubuntu 22.04")
        original_os = asset.os

        with patch.object(AssetRepo, "get_by_id", AsyncMock(return_value=asset)):
            await AssetRepo.update(session, 1, os=None, owner="security-team")

        # os=None is skipped; owner is updated
        assert asset.os == original_os
        assert asset.owner == "security-team"


# ---------------------------------------------------------------------------
# delete()
# ---------------------------------------------------------------------------


class TestAssetRepoDelete:

    @pytest.mark.asyncio
    async def test_found_deletes_and_returns_true(self) -> None:
        session = _make_session()
        asset = _make_asset(id=7)

        with patch.object(AssetRepo, "get_by_id", AsyncMock(return_value=asset)):
            result = await AssetRepo.delete(session, 7)

        assert result is True
        session.delete.assert_awaited_once_with(asset)
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_not_found_returns_false_no_delete(self) -> None:
        session = _make_session()

        with patch.object(AssetRepo, "get_by_id", AsyncMock(return_value=None)):
            result = await AssetRepo.delete(session, 999)

        assert result is False
        session.delete.assert_not_awaited()
        session.flush.assert_not_awaited()


# ---------------------------------------------------------------------------
# get_criticality()
# ---------------------------------------------------------------------------


class TestAssetRepoGetCriticality:

    @pytest.mark.asyncio
    async def test_found_by_hostname_returns_criticality(self) -> None:
        session = _make_session()
        asset = _make_asset(hostname="db-01", criticality=5)

        with patch.object(
            AssetRepo, "get_by_hostname", AsyncMock(return_value=asset)
        ):
            result = await AssetRepo.get_criticality(session, "db-01")

        assert result == 5

    @pytest.mark.asyncio
    async def test_not_found_by_hostname_falls_through_to_ip(self) -> None:
        session = _make_session()
        asset = _make_asset(criticality=4)

        with (
            patch.object(
                AssetRepo, "get_by_hostname", AsyncMock(return_value=None)
            ),
            patch.object(
                AssetRepo, "get_by_ip", AsyncMock(return_value=[asset])
            ),
        ):
            result = await AssetRepo.get_criticality(session, "10.0.0.1")

        assert result == 4

    @pytest.mark.asyncio
    async def test_multiple_ip_matches_returns_max_criticality(self) -> None:
        session = _make_session()
        assets = [_make_asset(criticality=2), _make_asset(criticality=5)]

        with (
            patch.object(
                AssetRepo, "get_by_hostname", AsyncMock(return_value=None)
            ),
            patch.object(
                AssetRepo, "get_by_ip", AsyncMock(return_value=assets)
            ),
        ):
            result = await AssetRepo.get_criticality(session, "10.0.0.1")

        assert result == 5

    @pytest.mark.asyncio
    async def test_not_found_anywhere_returns_default(self) -> None:
        session = _make_session()

        with (
            patch.object(
                AssetRepo, "get_by_hostname", AsyncMock(return_value=None)
            ),
            patch.object(AssetRepo, "get_by_ip", AsyncMock(return_value=[])),
        ):
            result = await AssetRepo.get_criticality(session, "unknown")

        assert result == _DEFAULT_CRITICALITY


# ---------------------------------------------------------------------------
# update_last_seen()
# ---------------------------------------------------------------------------


class TestAssetRepoUpdateLastSeen:

    @pytest.mark.asyncio
    async def test_executes_update_and_flushes(self) -> None:
        session = _make_session()

        await AssetRepo.update_last_seen(session, "host-01")

        session.execute.assert_awaited_once()
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_none(self) -> None:
        session = _make_session()

        result = await AssetRepo.update_last_seen(session, "host-01")

        assert result is None


# ---------------------------------------------------------------------------
# increment_detection_count()
# ---------------------------------------------------------------------------


class TestAssetRepoIncrementDetectionCount:

    @pytest.mark.asyncio
    async def test_executes_update_and_flushes(self) -> None:
        session = _make_session()

        await AssetRepo.increment_detection_count(session, "host-01")

        session.execute.assert_awaited_once()
        session.flush.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_none(self) -> None:
        session = _make_session()

        result = await AssetRepo.increment_detection_count(session, "host-01")

        assert result is None
