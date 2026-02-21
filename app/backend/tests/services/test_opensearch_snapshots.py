"""Unit tests for OpenSearchService snapshot management methods (feature 38.3).

All tests mock the underlying opensearch-py client — no real cluster needed.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.opensearch_client import OpenSearchService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_svc() -> tuple[OpenSearchService, MagicMock]:
    """Return (service, mock_client) with a connected mock."""
    svc = OpenSearchService()
    mock_client = MagicMock()
    # snapshot namespace methods are async
    mock_client.snapshot = MagicMock()
    svc._client = mock_client
    return svc, mock_client


# ---------------------------------------------------------------------------
# create_snapshot_repo
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_snapshot_repo_returns_false_when_unavailable() -> None:
    svc = OpenSearchService()  # _client is None
    result = await svc.create_snapshot_repo("mxtac-snapshots", "/backups/opensearch")
    assert result is False


@pytest.mark.asyncio
async def test_create_snapshot_repo_returns_true_on_success() -> None:
    svc, mock_client = _make_svc()
    mock_client.snapshot.create_repository = AsyncMock(return_value={"acknowledged": True})

    result = await svc.create_snapshot_repo("mxtac-snapshots", "/backups/opensearch")

    assert result is True
    mock_client.snapshot.create_repository.assert_called_once_with(
        repository="mxtac-snapshots",
        body={
            "type": "fs",
            "settings": {"location": "/backups/opensearch", "compress": True},
        },
    )


@pytest.mark.asyncio
async def test_create_snapshot_repo_returns_false_on_exception() -> None:
    svc, mock_client = _make_svc()
    mock_client.snapshot.create_repository = AsyncMock(
        side_effect=Exception("path.repo not set")
    )

    result = await svc.create_snapshot_repo("mxtac-snapshots", "/backups/opensearch")

    assert result is False


# ---------------------------------------------------------------------------
# create_snapshot
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_snapshot_returns_none_when_unavailable() -> None:
    svc = OpenSearchService()
    result = await svc.create_snapshot("mxtac-snapshots", "mxtac-20240115-000000")
    assert result is None


@pytest.mark.asyncio
async def test_create_snapshot_returns_response_on_success() -> None:
    svc, mock_client = _make_svc()
    mock_resp = {"snapshot": {"snapshot": "mxtac-20240115-000000", "state": "IN_PROGRESS"}}
    mock_client.snapshot.create = AsyncMock(return_value=mock_resp)

    result = await svc.create_snapshot("mxtac-snapshots", "mxtac-20240115-000000")

    assert result == mock_resp
    mock_client.snapshot.create.assert_called_once()
    call_kwargs = mock_client.snapshot.create.call_args.kwargs
    assert call_kwargs["repository"] == "mxtac-snapshots"
    assert call_kwargs["snapshot"] == "mxtac-20240115-000000"
    body = call_kwargs["body"]
    assert body["indices"] == "mxtac-*"
    assert body["include_global_state"] is False


@pytest.mark.asyncio
async def test_create_snapshot_returns_none_on_exception() -> None:
    svc, mock_client = _make_svc()
    mock_client.snapshot.create = AsyncMock(side_effect=Exception("repo not found"))

    result = await svc.create_snapshot("mxtac-snapshots", "mxtac-20240115-000000")

    assert result is None


# ---------------------------------------------------------------------------
# list_snapshots
# ---------------------------------------------------------------------------

_SNAPSHOT_RESPONSE = {
    "snapshots": [
        {
            "snapshot": "mxtac-20240114-000000",
            "state": "SUCCESS",
            "start_time": "2024-01-14T00:00:01.000Z",
            "end_time": "2024-01-14T00:00:10.000Z",
            "duration_in_millis": 9000,
            "indices": ["mxtac-events-2024.01.14"],
            "shards": {"total": 3, "successful": 3, "failed": 0},
        },
        {
            "snapshot": "mxtac-20240115-000000",
            "state": "IN_PROGRESS",
            "start_time": "2024-01-15T00:00:01.000Z",
            "end_time": "",
            "duration_in_millis": 0,
            "indices": ["mxtac-events-2024.01.15"],
            "stats": {"total": {"size_in_bytes": 1048576}},
            "shards": {"total": 3, "successful": 2, "failed": 0},
        },
    ]
}


@pytest.mark.asyncio
async def test_list_snapshots_returns_empty_when_unavailable() -> None:
    svc = OpenSearchService()
    result = await svc.list_snapshots("mxtac-snapshots")
    assert result == []


@pytest.mark.asyncio
async def test_list_snapshots_returns_parsed_list() -> None:
    svc, mock_client = _make_svc()
    mock_client.snapshot.get = AsyncMock(return_value=_SNAPSHOT_RESPONSE)

    result = await svc.list_snapshots("mxtac-snapshots")

    assert len(result) == 2

    completed = result[0]
    assert completed["name"] == "mxtac-20240114-000000"
    assert completed["state"] == "SUCCESS"
    assert completed["shards_total"] == 3
    assert completed["shards_successful"] == 3
    assert completed["shards_failed"] == 0
    assert completed["size_bytes"] == 0  # no stats field → default 0

    in_progress = result[1]
    assert in_progress["name"] == "mxtac-20240115-000000"
    assert in_progress["state"] == "IN_PROGRESS"
    assert in_progress["size_bytes"] == 1048576  # from stats.total.size_in_bytes


@pytest.mark.asyncio
async def test_list_snapshots_passes_correct_args() -> None:
    svc, mock_client = _make_svc()
    mock_client.snapshot.get = AsyncMock(return_value={"snapshots": []})

    await svc.list_snapshots("mxtac-snapshots")

    mock_client.snapshot.get.assert_called_once_with(
        repository="mxtac-snapshots",
        snapshot="_all",
    )


@pytest.mark.asyncio
async def test_list_snapshots_returns_empty_on_exception() -> None:
    svc, mock_client = _make_svc()
    mock_client.snapshot.get = AsyncMock(side_effect=Exception("repo missing"))

    result = await svc.list_snapshots("mxtac-snapshots")

    assert result == []


# ---------------------------------------------------------------------------
# restore_snapshot
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_restore_snapshot_returns_false_when_unavailable() -> None:
    svc = OpenSearchService()
    result = await svc.restore_snapshot("mxtac-snapshots", "mxtac-20240114-000000")
    assert result is False


@pytest.mark.asyncio
async def test_restore_snapshot_returns_true_on_success() -> None:
    svc, mock_client = _make_svc()
    mock_client.snapshot.restore = AsyncMock(return_value={"accepted": True})

    result = await svc.restore_snapshot("mxtac-snapshots", "mxtac-20240114-000000")

    assert result is True
    mock_client.snapshot.restore.assert_called_once()
    call_kwargs = mock_client.snapshot.restore.call_args.kwargs
    assert call_kwargs["repository"] == "mxtac-snapshots"
    assert call_kwargs["snapshot"] == "mxtac-20240114-000000"
    body = call_kwargs["body"]
    assert body["indices"] == "mxtac-*"
    assert body["include_global_state"] is False


@pytest.mark.asyncio
async def test_restore_snapshot_returns_false_on_exception() -> None:
    svc, mock_client = _make_svc()
    mock_client.snapshot.restore = AsyncMock(side_effect=Exception("snapshot missing"))

    result = await svc.restore_snapshot("mxtac-snapshots", "mxtac-20240114-000000")

    assert result is False


# ---------------------------------------------------------------------------
# delete_snapshot
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_snapshot_returns_false_when_unavailable() -> None:
    svc = OpenSearchService()
    result = await svc.delete_snapshot("mxtac-snapshots", "mxtac-20240114-000000")
    assert result is False


@pytest.mark.asyncio
async def test_delete_snapshot_returns_true_on_success() -> None:
    svc, mock_client = _make_svc()
    mock_client.snapshot.delete = AsyncMock(return_value={"acknowledged": True})

    result = await svc.delete_snapshot("mxtac-snapshots", "mxtac-20240114-000000")

    assert result is True
    mock_client.snapshot.delete.assert_called_once_with(
        repository="mxtac-snapshots",
        snapshot="mxtac-20240114-000000",
    )


@pytest.mark.asyncio
async def test_delete_snapshot_returns_false_on_exception() -> None:
    svc, mock_client = _make_svc()
    mock_client.snapshot.delete = AsyncMock(side_effect=Exception("not found"))

    result = await svc.delete_snapshot("mxtac-snapshots", "mxtac-20240114-000000")

    assert result is False
