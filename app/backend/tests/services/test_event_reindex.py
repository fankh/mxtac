"""Re-indexing events from PostgreSQL after an upgrade from the old index shape.

Earlier versions indexed the nested OCSF event into ``mxtac-events-YYYY.MM.DD``.
Searches read ``mxtac-events-v2-*`` only, so on the first start after an
upgrade the events are copied from PostgreSQL into the v2 indices.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event
from app.services.event_document import event_to_dict
from app.services.event_persister import reindex_legacy_events
from app.services.opensearch_client import OpenSearchService

_LEGACY_INDEX = "mxtac-events-2026.11.20"


class FakeIndexClient:
    """In-memory stand-in for the parts of ``AsyncOpenSearch`` re-indexing uses."""

    def __init__(self, legacy: dict[str, dict]) -> None:
        self.mappings = legacy                       # index name → mapping body
        self.docs: dict[str, dict[str, Any]] = {}    # v2 documents by ID
        self.bulk_calls = 0
        self.indices = MagicMock()
        self.indices.get_mapping = AsyncMock(side_effect=self._get_mapping)
        self.indices.put_mapping = AsyncMock(side_effect=self._put_mapping)

    async def _get_mapping(self, *, index: str, params: dict | None = None) -> dict:
        assert index == "mxtac-events-*,-mxtac-events-v2-*"
        return {name: {"mappings": body} for name, body in self.mappings.items()}

    async def _put_mapping(self, *, index: str, body: dict) -> dict:
        self.mappings[index].update(body)
        return {"acknowledged": True}

    async def search(self, *, index: str, body: dict, params: dict | None = None) -> dict:
        assert index == "mxtac-events-v2-*"
        wanted = body["query"]["ids"]["values"]
        return {"hits": {"hits": [{"_id": i} for i in wanted if i in self.docs]}}

    async def bulk(self, *, body: list[dict], params: dict | None = None) -> dict:
        self.bulk_calls += 1
        items = []
        for action, doc in zip(body[::2], body[1::2]):
            assert action["index"]["_index"].startswith("mxtac-events-v2-")
            self.docs[action["index"]["_id"]] = doc
            items.append({"index": {"_id": action["index"]["_id"], "status": 201}})
        return {"errors": False, "items": items}


def _service(client: FakeIndexClient) -> OpenSearchService:
    service = OpenSearchService()
    service._client = client
    return service


@pytest.fixture
async def events(db_session: AsyncSession) -> list[Event]:
    now = datetime.now(timezone.utc)
    rows = [
        Event(time=now - timedelta(hours=i), class_name="Process Activity", severity_id=3,
              hostname=f"host-{i}", username="alice", source="Webhook", summary=f"event {i}",
              raw={"process": {"cmd_line": f"cmd {i}"}, "metadata_product": "Webhook"})
        for i in range(5)
    ]
    db_session.add_all(rows)
    await db_session.flush()
    return rows


@pytest.fixture
def session_factory(db_session: AsyncSession):
    """Patch the persister's session factory to hand out the test session."""
    session_cm = MagicMock()
    session_cm.__aenter__ = AsyncMock(return_value=db_session)
    session_cm.__aexit__ = AsyncMock(return_value=False)
    with patch("app.services.event_persister.AsyncSessionLocal", return_value=session_cm):
        yield


async def test_no_legacy_index_means_nothing_to_do(events, session_factory) -> None:
    client = FakeIndexClient(legacy={})
    assert await reindex_legacy_events(_service(client)) == 0
    assert client.docs == {}
    assert client.bulk_calls == 0


async def test_events_are_copied_from_postgres_into_the_v2_index(events, session_factory) -> None:
    client = FakeIndexClient(legacy={_LEGACY_INDEX: {"properties": {}}})

    assert await reindex_legacy_events(_service(client)) == 5

    # Every event is indexed as the document the API returns for the row
    assert client.docs == {e.id: event_to_dict(e) for e in events}
    assert all(doc["hostname"] and doc["summary"] for doc in client.docs.values())
    # The legacy index is marked, so the next start does not run again
    assert client.mappings[_LEGACY_INDEX]["_meta"] == {"mxtac_reindexed": True}

    assert await reindex_legacy_events(_service(client)) == 0
    assert client.bulk_calls == 1


async def test_interrupted_run_resumes_without_duplicates(events, session_factory) -> None:
    """Events that already have a v2 document are skipped."""
    client = FakeIndexClient(legacy={_LEGACY_INDEX: {"properties": {}}})
    already = events[0]
    client.docs[already.id] = {"id": already.id, "marker": "indexed by the live pipeline"}

    assert await reindex_legacy_events(_service(client)) == 4

    assert set(client.docs) == {e.id for e in events}
    assert client.docs[already.id]["marker"] == "indexed by the live pipeline"


async def test_batches_cover_all_events(events, session_factory) -> None:
    client = FakeIndexClient(legacy={_LEGACY_INDEX: {"properties": {}}})
    with patch("app.services.event_persister._REINDEX_BATCH_SIZE", 2):
        assert await reindex_legacy_events(_service(client)) == 5
    assert client.bulk_calls == 3
    assert set(client.docs) == {e.id for e in events}


async def test_events_older_than_the_retention_are_not_copied(
    db_session: AsyncSession, events, session_factory,
) -> None:
    old = Event(time=datetime.now(timezone.utc) - timedelta(days=200), summary="old",
                created_at=datetime.now(timezone.utc) - timedelta(days=200))
    db_session.add(old)
    await db_session.flush()

    client = FakeIndexClient(legacy={_LEGACY_INDEX: {"properties": {}}})
    assert await reindex_legacy_events(_service(client)) == 5
    assert old.id not in client.docs


async def test_unavailable_opensearch_is_a_no_op(events, session_factory) -> None:
    assert await reindex_legacy_events(OpenSearchService()) == 0
