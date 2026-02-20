"""Tests for GET /metrics — Prometheus format (feature 21.3).

Coverage:
  /metrics endpoint:
  - Returns 200 OK without authentication
  - Content-Type is text/plain (Prometheus exposition format)
  - Response body is non-empty
  - Response body contains HELP comment lines (# HELP ...)
  - Response body contains TYPE comment lines (# TYPE ...)
  - Response body exposes MxTac custom metrics (mxtac_ prefix)
  - Auth headers do not change the response
  - POST /metrics is rejected with 405
  - PUT /metrics is rejected with 405
  - DELETE /metrics is rejected with 405
  - Idempotent: repeated calls return 200

  MxTac custom metrics (app/core/metrics.py):
  - mxtac_alerts_processed_total is present
  - mxtac_alerts_deduplicated_total is present
  - mxtac_pipeline_latency_seconds is present
  - mxtac_sigma_rules_loaded is present
  - mxtac_sigma_matches_total is present
  - mxtac_events_ingested_total is present
  - mxtac_connectors_active is present
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient


METRICS_URL = "/metrics"


# ---------------------------------------------------------------------------
# Basic HTTP contract
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_returns_200(client: AsyncClient) -> None:
    """/metrics returns 200 OK without authentication."""
    resp = await client.get(METRICS_URL)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_metrics_content_type_is_text_plain(client: AsyncClient) -> None:
    """/metrics Content-Type is text/plain (Prometheus exposition format)."""
    resp = await client.get(METRICS_URL)
    assert "text/plain" in resp.headers["content-type"]


@pytest.mark.asyncio
async def test_metrics_body_is_non_empty(client: AsyncClient) -> None:
    """/metrics response body is non-empty."""
    resp = await client.get(METRICS_URL)
    assert len(resp.text) > 0


@pytest.mark.asyncio
async def test_metrics_no_auth_required(client: AsyncClient) -> None:
    """/metrics returns 200 without an Authorization header."""
    resp = await client.get(METRICS_URL)
    assert resp.status_code == 200
    assert "Authorization" not in resp.request.headers


@pytest.mark.asyncio
async def test_metrics_with_auth_headers_still_200(
    client: AsyncClient,
    analyst_headers: dict[str, str],
) -> None:
    """/metrics returns 200 even when a valid Bearer token is supplied."""
    resp = await client.get(METRICS_URL, headers=analyst_headers)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_metrics_idempotent(client: AsyncClient) -> None:
    """/metrics returns 200 on repeated calls."""
    for _ in range(3):
        resp = await client.get(METRICS_URL)
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Prometheus exposition format
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_contains_help_lines(client: AsyncClient) -> None:
    """/metrics body contains at least one # HELP comment line."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    help_lines = [l for l in lines if l.startswith("# HELP ")]
    assert len(help_lines) > 0, "Expected at least one '# HELP' line in /metrics output"


@pytest.mark.asyncio
async def test_metrics_contains_type_lines(client: AsyncClient) -> None:
    """/metrics body contains at least one # TYPE comment line."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    type_lines = [l for l in lines if l.startswith("# TYPE ")]
    assert len(type_lines) > 0, "Expected at least one '# TYPE' line in /metrics output"


@pytest.mark.asyncio
async def test_metrics_help_and_type_lines_are_balanced(client: AsyncClient) -> None:
    """Every metric has both a # HELP and a # TYPE line."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    help_names = {l.split()[2] for l in lines if l.startswith("# HELP ")}
    type_names = {l.split()[2] for l in lines if l.startswith("# TYPE ")}
    # Every HELP should have a corresponding TYPE
    assert help_names == type_names, (
        f"Mismatched HELP/TYPE sets — HELP-only: {help_names - type_names}, "
        f"TYPE-only: {type_names - help_names}"
    )


# ---------------------------------------------------------------------------
# HTTP method restrictions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_post_not_allowed(client: AsyncClient) -> None:
    """/metrics rejects POST with 405."""
    resp = await client.post(METRICS_URL)
    assert resp.status_code == 405


@pytest.mark.asyncio
async def test_metrics_put_not_allowed(client: AsyncClient) -> None:
    """/metrics rejects PUT with 405."""
    resp = await client.put(METRICS_URL)
    assert resp.status_code == 405


@pytest.mark.asyncio
async def test_metrics_delete_not_allowed(client: AsyncClient) -> None:
    """/metrics rejects DELETE with 405."""
    resp = await client.delete(METRICS_URL)
    assert resp.status_code == 405


# ---------------------------------------------------------------------------
# MxTac custom metrics — alert pipeline (app/core/metrics.py)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_contains_alerts_processed_total(client: AsyncClient) -> None:
    """/metrics exposes mxtac_alerts_processed_total counter."""
    resp = await client.get(METRICS_URL)
    assert "mxtac_alerts_processed_total" in resp.text


@pytest.mark.asyncio
async def test_metrics_contains_alerts_deduplicated_total(client: AsyncClient) -> None:
    """/metrics exposes mxtac_alerts_deduplicated_total counter."""
    resp = await client.get(METRICS_URL)
    assert "mxtac_alerts_deduplicated_total" in resp.text


@pytest.mark.asyncio
async def test_metrics_contains_pipeline_latency_seconds(client: AsyncClient) -> None:
    """/metrics exposes mxtac_pipeline_latency_seconds histogram."""
    resp = await client.get(METRICS_URL)
    assert "mxtac_pipeline_latency_seconds" in resp.text


# ---------------------------------------------------------------------------
# MxTac custom metrics — Sigma engine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_contains_sigma_rules_loaded(client: AsyncClient) -> None:
    """/metrics exposes mxtac_sigma_rules_loaded gauge."""
    resp = await client.get(METRICS_URL)
    assert "mxtac_sigma_rules_loaded" in resp.text


@pytest.mark.asyncio
async def test_metrics_contains_sigma_matches_total(client: AsyncClient) -> None:
    """/metrics exposes mxtac_sigma_matches_total counter."""
    resp = await client.get(METRICS_URL)
    assert "mxtac_sigma_matches_total" in resp.text


# ---------------------------------------------------------------------------
# MxTac custom metrics — event ingestion
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_contains_events_ingested_total(client: AsyncClient) -> None:
    """/metrics exposes mxtac_events_ingested_total counter."""
    resp = await client.get(METRICS_URL)
    assert "mxtac_events_ingested_total" in resp.text


# ---------------------------------------------------------------------------
# MxTac custom metrics — connectors
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_contains_connectors_active(client: AsyncClient) -> None:
    """/metrics exposes mxtac_connectors_active gauge."""
    resp = await client.get(METRICS_URL)
    assert "mxtac_connectors_active" in resp.text


# ---------------------------------------------------------------------------
# MxTac custom metrics — all mxtac_ metrics present
# ---------------------------------------------------------------------------


_EXPECTED_MXTAC_METRICS = [
    "mxtac_alerts_processed_total",
    "mxtac_alerts_deduplicated_total",
    "mxtac_pipeline_latency_seconds",
    "mxtac_sigma_rules_loaded",
    "mxtac_sigma_matches_total",
    "mxtac_events_ingested_total",
    "mxtac_connectors_active",
]


@pytest.mark.asyncio
async def test_metrics_all_mxtac_metrics_present(client: AsyncClient) -> None:
    """All expected MxTac custom metrics are present in /metrics output."""
    resp = await client.get(METRICS_URL)
    body = resp.text
    missing = [name for name in _EXPECTED_MXTAC_METRICS if name not in body]
    assert not missing, f"Missing metrics in /metrics output: {missing}"


@pytest.mark.asyncio
async def test_metrics_mxtac_metrics_have_help_lines(client: AsyncClient) -> None:
    """All MxTac custom metrics have # HELP lines describing them."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    help_names = {l.split()[2] for l in lines if l.startswith("# HELP ")}
    missing_help = [name for name in _EXPECTED_MXTAC_METRICS if name not in help_names]
    assert not missing_help, f"Missing # HELP lines for metrics: {missing_help}"


@pytest.mark.asyncio
async def test_metrics_mxtac_metrics_have_type_lines(client: AsyncClient) -> None:
    """All MxTac custom metrics have # TYPE lines declaring their type."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    type_names = {l.split()[2] for l in lines if l.startswith("# TYPE ")}
    # Histogram metrics appear with _bucket, _count, _sum suffixes in the body
    # but the TYPE declaration uses the base name
    missing_type = [name for name in _EXPECTED_MXTAC_METRICS if name not in type_names]
    assert not missing_type, f"Missing # TYPE lines for metrics: {missing_type}"


# ---------------------------------------------------------------------------
# Metric type declarations
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_declared_as_histogram(client: AsyncClient) -> None:
    """/metrics declares mxtac_pipeline_latency_seconds as a histogram."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    type_line = next(
        (l for l in lines if l.startswith("# TYPE mxtac_pipeline_latency_seconds")),
        None,
    )
    assert type_line is not None, "No # TYPE line for mxtac_pipeline_latency_seconds"
    assert "histogram" in type_line


@pytest.mark.asyncio
async def test_metrics_sigma_rules_loaded_declared_as_gauge(client: AsyncClient) -> None:
    """/metrics declares mxtac_sigma_rules_loaded as a gauge."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    type_line = next(
        (l for l in lines if l.startswith("# TYPE mxtac_sigma_rules_loaded")),
        None,
    )
    assert type_line is not None, "No # TYPE line for mxtac_sigma_rules_loaded"
    assert "gauge" in type_line


@pytest.mark.asyncio
async def test_metrics_connectors_active_declared_as_gauge(client: AsyncClient) -> None:
    """/metrics declares mxtac_connectors_active as a gauge."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    type_line = next(
        (l for l in lines if l.startswith("# TYPE mxtac_connectors_active")),
        None,
    )
    assert type_line is not None, "No # TYPE line for mxtac_connectors_active"
    assert "gauge" in type_line


@pytest.mark.asyncio
async def test_metrics_alerts_processed_declared_as_counter(client: AsyncClient) -> None:
    """/metrics declares mxtac_alerts_processed_total as a counter."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    type_line = next(
        (l for l in lines if l.startswith("# TYPE mxtac_alerts_processed_total")),
        None,
    )
    assert type_line is not None, "No # TYPE line for mxtac_alerts_processed_total"
    assert "counter" in type_line
