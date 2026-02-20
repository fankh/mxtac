"""Tests for GET /metrics — Prometheus format (feature 21.3),
mxtac_alerts_processed_total{severity} counter (feature 21.4),
mxtac_alerts_deduplicated_total counter (feature 21.5),
mxtac_rule_matches_total{rule_id,level} counter (feature 21.6), and
mxtac_pipeline_latency_seconds histogram (feature 21.7).

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
  - mxtac_rule_matches_total is present
  - mxtac_events_ingested_total is present
  - mxtac_connectors_active is present

  mxtac_alerts_processed_total{severity} — feature 21.4:
  - Severity label appears in /metrics output after incrementing the counter
  - All four Sigma severity levels (low/medium/high/critical) produce distinct labeled series
  - Label key is "severity" (not "level" or other names)
  - Counter declared as counter type (not gauge/histogram)

  mxtac_alerts_deduplicated_total — feature 21.5:
  - Counter declared as counter type (not gauge/histogram)
  - Counter value is >= 1.0 after alerts_deduplicated.inc()
  - Counter has no labels (label-free counter — dedup is not partitioned by severity)

  mxtac_rule_matches_total{rule_id,level} — feature 21.6:
  - Counter declared as counter type (not gauge/histogram)
  - Counter appears in /metrics after incrementing with rule_id and level labels
  - Both rule_id and level labels are present in the emitted series
  - Distinct rule_id values produce separate labelled series
  - All five Sigma levels (informational/low/medium/high/critical) work as label values
  - Counter value is >= 1.0 after rule_matches.labels(...).inc()

  mxtac_pipeline_latency_seconds — feature 21.7:
  - Histogram declared as histogram type (not counter/gauge)
  - _bucket lines appear in /metrics after observe()
  - _count line appears in /metrics after observe()
  - _sum line appears in /metrics after observe()
  - le= label is present on bucket lines
  - _count value is >= 1 after one observe()
  - _sum value is >= 0 after observe() with a non-negative duration
  - All custom bucket boundaries (0.005..10.0) appear as le= labels
  - +Inf bucket is present
  - observe() can be called multiple times without error
  - _count increments by 1 for each observe() call
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.core.metrics import alerts_deduplicated, alerts_processed, pipeline_latency, rule_matches


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
    "mxtac_rule_matches_total",
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


# ---------------------------------------------------------------------------
# mxtac_alerts_processed_total{severity} — feature 21.4
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_alerts_processed_severity_label_appears_after_increment(
    client: AsyncClient,
) -> None:
    """After incrementing the counter with a severity label, the label appears in /metrics.

    The Prometheus text format only emits label series that have been observed
    at least once.  Calling alerts_processed.labels(severity=...).inc() causes
    the labelled series to appear in the output.
    """
    alerts_processed.labels(severity="high").inc()
    resp = await client.get(METRICS_URL)
    assert 'severity="high"' in resp.text, (
        "Expected 'severity=\"high\"' label in /metrics after incrementing the counter"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("level", ["low", "medium", "high", "critical"])
async def test_metrics_alerts_processed_all_sigma_levels_produce_labeled_series(
    client: AsyncClient,
    level: str,
) -> None:
    """Each Sigma severity level produces a distinct labelled series in /metrics.

    Verifies that alerts_processed.labels(severity=<level>).inc() for every
    standard Sigma level (low, medium, high, critical) results in a separate
    'severity="<level>"' series visible in the Prometheus exposition output.
    """
    alerts_processed.labels(severity=level).inc()
    resp = await client.get(METRICS_URL)
    assert f'severity="{level}"' in resp.text, (
        f"Expected 'severity=\"{level}\"' label in /metrics output"
    )


@pytest.mark.asyncio
async def test_metrics_alerts_processed_label_key_is_severity(client: AsyncClient) -> None:
    """The label key for mxtac_alerts_processed_total must be 'severity' (not 'level').

    The Prometheus label name must match what the AlertManager emits:
      alerts_processed.labels(severity=severity_label).inc()
    """
    alerts_processed.labels(severity="medium").inc()
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    # Find lines with the metric name and verify the label key is 'severity'
    metric_lines = [
        l for l in lines
        if l.startswith("mxtac_alerts_processed_total{") and "severity=" in l
    ]
    assert len(metric_lines) > 0, (
        "Expected at least one mxtac_alerts_processed_total{severity=...} line in /metrics"
    )
    for line in metric_lines:
        assert "severity=" in line, f"Label key must be 'severity'; got: {line}"


@pytest.mark.asyncio
async def test_metrics_alerts_processed_counter_increments_are_cumulative(
    client: AsyncClient,
) -> None:
    """Prometheus counter values for mxtac_alerts_processed_total must be >= 1 after inc().

    Counters are monotonically increasing.  After at least one increment the
    reported value must be a positive number (>= 1.0 in the text exposition).
    """
    alerts_processed.labels(severity="critical").inc()
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    critical_lines = [
        l for l in lines
        if l.startswith("mxtac_alerts_processed_total") and 'severity="critical"' in l
    ]
    assert len(critical_lines) > 0, (
        "Expected mxtac_alerts_processed_total{severity='critical'} line in /metrics"
    )
    # The value is the last whitespace-separated token; must be a positive float
    value = float(critical_lines[0].split()[-1])
    assert value >= 1.0, (
        f"Counter value must be >= 1.0 after inc(); got {value}"
    )


# ---------------------------------------------------------------------------
# mxtac_alerts_deduplicated_total — feature 21.5
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_alerts_deduplicated_declared_as_counter(client: AsyncClient) -> None:
    """/metrics declares mxtac_alerts_deduplicated_total as a counter."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    type_line = next(
        (l for l in lines if l.startswith("# TYPE mxtac_alerts_deduplicated_total")),
        None,
    )
    assert type_line is not None, "No # TYPE line for mxtac_alerts_deduplicated_total"
    assert "counter" in type_line


@pytest.mark.asyncio
async def test_metrics_alerts_deduplicated_value_increases_after_inc(
    client: AsyncClient,
) -> None:
    """After alerts_deduplicated.inc(), the counter value in /metrics must be >= 1.

    Counters are monotonically increasing.  One increment is sufficient to
    produce a positive value in the Prometheus text exposition.
    """
    alerts_deduplicated.inc()
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    dedup_lines = [
        l for l in lines
        if l.startswith("mxtac_alerts_deduplicated_total") and not l.startswith("#")
    ]
    assert len(dedup_lines) > 0, (
        "Expected a mxtac_alerts_deduplicated_total line in /metrics after inc()"
    )
    value = float(dedup_lines[0].split()[-1])
    assert value >= 1.0, (
        f"Counter value must be >= 1.0 after inc(); got {value}"
    )


@pytest.mark.asyncio
async def test_metrics_alerts_deduplicated_has_no_labels(client: AsyncClient) -> None:
    """mxtac_alerts_deduplicated_total is a label-free counter.

    Deduplication is not partitioned by severity; the counter has no label
    dimensions.  The metric line must not contain a '{...}' label set.
    """
    alerts_deduplicated.inc()
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    # Find the data line(s) for this metric (not comments)
    dedup_lines = [
        l for l in lines
        if l.startswith("mxtac_alerts_deduplicated_total") and not l.startswith("#")
    ]
    assert len(dedup_lines) > 0, (
        "Expected a mxtac_alerts_deduplicated_total data line in /metrics"
    )
    for line in dedup_lines:
        # A label-free counter line looks like:
        #   mxtac_alerts_deduplicated_total_total 3.0
        # NOT like:
        #   mxtac_alerts_deduplicated_total{foo="bar"} 3.0
        assert "{" not in line, (
            f"mxtac_alerts_deduplicated_total must have no labels; got: {line}"
        )


# ---------------------------------------------------------------------------
# mxtac_rule_matches_total{rule_id,level} — feature 21.6
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_metrics_rule_matches_declared_as_counter(client: AsyncClient) -> None:
    """/metrics declares mxtac_rule_matches_total as a counter."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    type_line = next(
        (l for l in lines if l.startswith("# TYPE mxtac_rule_matches_total")),
        None,
    )
    assert type_line is not None, "No # TYPE line for mxtac_rule_matches_total"
    assert "counter" in type_line


@pytest.mark.asyncio
async def test_metrics_rule_matches_labels_appear_after_increment(
    client: AsyncClient,
) -> None:
    """After incrementing with rule_id and level labels, both appear in /metrics.

    The Prometheus text format only emits label series that have been observed
    at least once.  Calling rule_matches.labels(rule_id=..., level=...).inc()
    causes the labelled series to appear in the output.
    """
    rule_matches.labels(rule_id="test-rule-001", level="high").inc()
    resp = await client.get(METRICS_URL)
    assert 'rule_id="test-rule-001"' in resp.text, (
        "Expected 'rule_id=\"test-rule-001\"' label in /metrics after incrementing"
    )
    assert 'level="high"' in resp.text, (
        "Expected 'level=\"high\"' label in /metrics after incrementing"
    )


@pytest.mark.asyncio
async def test_metrics_rule_matches_distinct_rule_ids_produce_separate_series(
    client: AsyncClient,
) -> None:
    """Different rule_id values produce separate labelled series in /metrics."""
    rule_matches.labels(rule_id="rule-aaa", level="medium").inc()
    rule_matches.labels(rule_id="rule-bbb", level="medium").inc()
    resp = await client.get(METRICS_URL)
    assert 'rule_id="rule-aaa"' in resp.text, (
        "Expected 'rule_id=\"rule-aaa\"' in /metrics"
    )
    assert 'rule_id="rule-bbb"' in resp.text, (
        "Expected 'rule_id=\"rule-bbb\"' in /metrics"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("level", ["informational", "low", "medium", "high", "critical"])
async def test_metrics_rule_matches_all_sigma_levels_accepted(
    client: AsyncClient,
    level: str,
) -> None:
    """All five Sigma severity levels are valid label values for mxtac_rule_matches_total."""
    rule_matches.labels(rule_id=f"rule-{level}", level=level).inc()
    resp = await client.get(METRICS_URL)
    assert f'level="{level}"' in resp.text, (
        f"Expected 'level=\"{level}\"' in /metrics output"
    )


@pytest.mark.asyncio
async def test_metrics_rule_matches_value_is_positive_after_increment(
    client: AsyncClient,
) -> None:
    """Counter value for mxtac_rule_matches_total must be >= 1.0 after inc().

    Counters are monotonically increasing.  One increment is sufficient to
    produce a positive value in the Prometheus text exposition.
    """
    rule_matches.labels(rule_id="rule-value-check", level="critical").inc()
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    match_lines = [
        l for l in lines
        if l.startswith("mxtac_rule_matches_total") and 'rule_id="rule-value-check"' in l
    ]
    assert len(match_lines) > 0, (
        "Expected mxtac_rule_matches_total{rule_id='rule-value-check',...} line in /metrics"
    )
    value = float(match_lines[0].split()[-1])
    assert value >= 1.0, (
        f"Counter value must be >= 1.0 after inc(); got {value}"
    )


@pytest.mark.asyncio
async def test_metrics_rule_matches_contains_both_label_keys(
    client: AsyncClient,
) -> None:
    """The mxtac_rule_matches_total series line contains both rule_id and level label keys."""
    rule_matches.labels(rule_id="rule-labels-check", level="low").inc()
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    match_lines = [
        l for l in lines
        if l.startswith("mxtac_rule_matches_total{") and 'rule_id="rule-labels-check"' in l
    ]
    assert len(match_lines) > 0, (
        "Expected at least one mxtac_rule_matches_total{...} data line"
    )
    for line in match_lines:
        assert "rule_id=" in line, f"Missing 'rule_id' label in: {line}"
        assert "level=" in line, f"Missing 'level' label in: {line}"


# ---------------------------------------------------------------------------
# mxtac_pipeline_latency_seconds — feature 21.7
# ---------------------------------------------------------------------------
#
# The histogram measures end-to-end alert processing latency in seconds.
# Custom buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
# Implementation: app/core/metrics.py (pipeline_latency Histogram)
#                 app/services/alert_manager.py (pipeline_latency.observe())
#
# Prometheus exposition format for histograms:
#   mxtac_pipeline_latency_seconds_bucket{le="0.005"} 0.0
#   ...
#   mxtac_pipeline_latency_seconds_bucket{le="+Inf"}  N
#   mxtac_pipeline_latency_seconds_count              N
#   mxtac_pipeline_latency_seconds_sum                S

_PIPELINE_LATENCY_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_declared_as_histogram_type(
    client: AsyncClient,
) -> None:
    """/metrics declares mxtac_pipeline_latency_seconds as histogram type."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    type_line = next(
        (l for l in lines if l.startswith("# TYPE mxtac_pipeline_latency_seconds")),
        None,
    )
    assert type_line is not None, "No # TYPE line for mxtac_pipeline_latency_seconds"
    assert "histogram" in type_line, (
        f"Expected 'histogram' in TYPE line; got: {type_line}"
    )


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_bucket_lines_appear_after_observe(
    client: AsyncClient,
) -> None:
    """After observe(), _bucket lines appear in /metrics output."""
    pipeline_latency.observe(0.042)
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    bucket_lines = [
        l for l in lines
        if l.startswith("mxtac_pipeline_latency_seconds_bucket{")
    ]
    assert len(bucket_lines) > 0, (
        "Expected mxtac_pipeline_latency_seconds_bucket{...} lines in /metrics after observe()"
    )


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_count_line_appears_after_observe(
    client: AsyncClient,
) -> None:
    """After observe(), _count line appears in /metrics output."""
    pipeline_latency.observe(0.010)
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    count_lines = [
        l for l in lines
        if l.startswith("mxtac_pipeline_latency_seconds_count")
    ]
    assert len(count_lines) > 0, (
        "Expected mxtac_pipeline_latency_seconds_count line in /metrics after observe()"
    )


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_sum_line_appears_after_observe(
    client: AsyncClient,
) -> None:
    """After observe(), _sum line appears in /metrics output."""
    pipeline_latency.observe(0.010)
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    sum_lines = [
        l for l in lines
        if l.startswith("mxtac_pipeline_latency_seconds_sum")
    ]
    assert len(sum_lines) > 0, (
        "Expected mxtac_pipeline_latency_seconds_sum line in /metrics after observe()"
    )


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_bucket_lines_have_le_label(
    client: AsyncClient,
) -> None:
    """Bucket lines must contain the 'le=' label (upper bound)."""
    pipeline_latency.observe(0.010)
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    bucket_lines = [
        l for l in lines
        if l.startswith("mxtac_pipeline_latency_seconds_bucket{")
    ]
    assert len(bucket_lines) > 0, (
        "Expected at least one mxtac_pipeline_latency_seconds_bucket{...} line"
    )
    for line in bucket_lines:
        assert "le=" in line, f"Bucket line must contain 'le=' label; got: {line}"


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_count_is_positive_after_observe(
    client: AsyncClient,
) -> None:
    """_count value must be >= 1 after one pipeline_latency.observe() call."""
    pipeline_latency.observe(0.025)
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    count_lines = [
        l for l in lines
        if l.startswith("mxtac_pipeline_latency_seconds_count") and not l.startswith("#")
    ]
    assert len(count_lines) > 0, (
        "Expected mxtac_pipeline_latency_seconds_count data line"
    )
    value = float(count_lines[0].split()[-1])
    assert value >= 1.0, (
        f"_count must be >= 1 after observe(); got {value}"
    )


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_sum_is_nonnegative_after_observe(
    client: AsyncClient,
) -> None:
    """_sum value must be >= 0 after observe() with a non-negative duration."""
    pipeline_latency.observe(0.050)
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    sum_lines = [
        l for l in lines
        if l.startswith("mxtac_pipeline_latency_seconds_sum") and not l.startswith("#")
    ]
    assert len(sum_lines) > 0, (
        "Expected mxtac_pipeline_latency_seconds_sum data line"
    )
    value = float(sum_lines[0].split()[-1])
    assert value >= 0.0, (
        f"_sum must be >= 0 after observe(); got {value}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("bucket", _PIPELINE_LATENCY_BUCKETS)
async def test_metrics_pipeline_latency_all_custom_buckets_present(
    client: AsyncClient,
    bucket: float,
) -> None:
    """Each custom bucket boundary appears as a le= label in /metrics output.

    The histogram is configured with 11 custom upper bounds:
    [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    All must appear as le= values in the _bucket series.
    """
    pipeline_latency.observe(0.001)
    resp = await client.get(METRICS_URL)
    # Prometheus formats floats as-is; match the string representation
    bucket_str = str(bucket) if "." in str(bucket) else f"{bucket}.0"
    assert f'le="{bucket_str}"' in resp.text, (
        f"Expected bucket le=\"{bucket_str}\" in /metrics for custom bucket {bucket}"
    )


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_inf_bucket_present(
    client: AsyncClient,
) -> None:
    """+Inf bucket must always be present in histogram output."""
    pipeline_latency.observe(0.001)
    resp = await client.get(METRICS_URL)
    assert 'le="+Inf"' in resp.text, (
        "Expected le=\"+Inf\" bucket in /metrics for mxtac_pipeline_latency_seconds"
    )


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_count_increments_per_observe(
    client: AsyncClient,
) -> None:
    """_count must increment by exactly 1 for each observe() call."""
    # Read baseline count
    resp_before = await client.get(METRICS_URL)
    lines_before = resp_before.text.splitlines()
    count_lines_before = [
        l for l in lines_before
        if l.startswith("mxtac_pipeline_latency_seconds_count") and not l.startswith("#")
    ]
    before = float(count_lines_before[0].split()[-1]) if count_lines_before else 0.0

    pipeline_latency.observe(0.100)
    pipeline_latency.observe(0.200)
    pipeline_latency.observe(0.300)

    resp_after = await client.get(METRICS_URL)
    lines_after = resp_after.text.splitlines()
    count_lines_after = [
        l for l in lines_after
        if l.startswith("mxtac_pipeline_latency_seconds_count") and not l.startswith("#")
    ]
    after = float(count_lines_after[0].split()[-1])

    assert after == before + 3, (
        f"_count must increment by 1 per observe(); expected {before + 3}, got {after}"
    )


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_observe_zero_duration(
    client: AsyncClient,
) -> None:
    """observe(0.0) must be accepted without error and increment _count."""
    resp_before = await client.get(METRICS_URL)
    lines_before = resp_before.text.splitlines()
    count_before_lines = [
        l for l in lines_before
        if l.startswith("mxtac_pipeline_latency_seconds_count") and not l.startswith("#")
    ]
    before = float(count_before_lines[0].split()[-1]) if count_before_lines else 0.0

    pipeline_latency.observe(0.0)

    resp_after = await client.get(METRICS_URL)
    lines_after = resp_after.text.splitlines()
    count_after_lines = [
        l for l in lines_after
        if l.startswith("mxtac_pipeline_latency_seconds_count") and not l.startswith("#")
    ]
    after = float(count_after_lines[0].split()[-1])

    assert after == before + 1, (
        f"observe(0.0) must increment _count; expected {before + 1}, got {after}"
    )


@pytest.mark.asyncio
async def test_metrics_pipeline_latency_help_line_present(
    client: AsyncClient,
) -> None:
    """/metrics must include a # HELP line for mxtac_pipeline_latency_seconds."""
    resp = await client.get(METRICS_URL)
    lines = resp.text.splitlines()
    help_line = next(
        (l for l in lines if l.startswith("# HELP mxtac_pipeline_latency_seconds")),
        None,
    )
    assert help_line is not None, (
        "Expected '# HELP mxtac_pipeline_latency_seconds' line in /metrics"
    )
    assert len(help_line.split()) > 3, (
        "# HELP line must contain a non-empty description"
    )
