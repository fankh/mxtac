"""MxTac Prometheus metrics registry — feature 21.3.

All custom prometheus_client metrics are defined here to avoid duplicate
registration errors when modules are reloaded (e.g., during hot-reload or
test runs).  Import metric objects from this module rather than defining
them inline in service modules.

Metrics exposed at GET /metrics (Prometheus text format):

  Alert pipeline
  ──────────────
  mxtac_alerts_processed_total{severity}   Counter  — alerts through the pipeline
  mxtac_alerts_deduplicated_total          Counter  — alerts dropped by dedup
  mxtac_pipeline_latency_seconds           Histogram — end-to-end latency

  Sigma engine
  ─────────────
  mxtac_sigma_rules_loaded                 Gauge    — loaded rule count
  mxtac_sigma_matches_total{level}         Counter  — rule match events

  Event ingestion
  ───────────────
  mxtac_events_ingested_total{source}      Counter  — raw events into the pipeline

  Connectors
  ──────────
  mxtac_connectors_active                  Gauge    — running connector count
"""

from prometheus_client import Counter, Gauge, Histogram

# ---------------------------------------------------------------------------
# Alert pipeline
# ---------------------------------------------------------------------------

alerts_processed = Counter(
    "mxtac_alerts_processed_total",
    "Total alerts processed by the alert manager pipeline",
    ["severity"],
)

alerts_deduplicated = Counter(
    "mxtac_alerts_deduplicated_total",
    "Total alerts dropped as duplicates within the deduplication window",
)

pipeline_latency = Histogram(
    "mxtac_pipeline_latency_seconds",
    "End-to-end alert pipeline processing latency in seconds",
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

# ---------------------------------------------------------------------------
# Sigma engine
# ---------------------------------------------------------------------------

sigma_rules_loaded = Gauge(
    "mxtac_sigma_rules_loaded",
    "Number of Sigma detection rules currently loaded in the engine",
)

sigma_matches = Counter(
    "mxtac_sigma_matches_total",
    "Total Sigma rule match events emitted by the evaluation engine",
    ["level"],
)

# ---------------------------------------------------------------------------
# Event ingestion
# ---------------------------------------------------------------------------

events_ingested = Counter(
    "mxtac_events_ingested_total",
    "Total raw events ingested into the normalizer pipeline",
    ["source"],
)

# ---------------------------------------------------------------------------
# Connectors
# ---------------------------------------------------------------------------

connectors_active = Gauge(
    "mxtac_connectors_active",
    "Number of connectors currently in the running state",
)
