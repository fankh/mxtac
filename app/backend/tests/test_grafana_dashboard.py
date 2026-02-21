"""Tests for feature 21.9 — Grafana dashboard pre-built JSON.

Validates the structure and correctness of the Grafana dashboard JSON file
shipped at deploy/monitoring/grafana/dashboards/mxtac-overview.json and the
accompanying Grafana provisioning YAML files.

Coverage:
  mxtac-overview.json — dashboard structure:
  - File exists at the expected path relative to the repo root
  - File is valid JSON
  - Top-level required fields are present (title, uid, panels, schemaVersion,
    templating, time)
  - Dashboard uid is 'mxtac-overview'
  - schemaVersion >= 36 (Grafana 9.x+)
  - At least one datasource template variable is defined
  - Dashboard contains at least five row separator panels (major sections)
  - All panels have unique IDs
  - All panels have a gridPos with h/w/x/y keys
  - All non-row panels reference the ${datasource} variable
  - All non-row panels have at least one PromQL target
  - Every PromQL target references a known MxTac metric
  - Dashboard refresh interval is set
  - Dashboard tags include 'mxtac'

  Prometheus provisioning (prometheus.yml):
  - File exists
  - Is valid YAML
  - Contains the mxtac-backend scrape job targeting port 8080

  Grafana datasource provisioning:
  - File exists
  - Is valid YAML
  - Defines a Prometheus datasource named 'Prometheus'
  - Datasource uid matches the dashboard variable default

  Grafana dashboard provisioning (mxtac.yml):
  - File exists
  - Is valid YAML
  - provider path is '/etc/grafana/dashboards'
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[4]  # .../mitre-attack/mxtac
_MONITORING = _REPO_ROOT / "app" / "deploy" / "monitoring"
_DASHBOARD_JSON = _MONITORING / "grafana" / "dashboards" / "mxtac-overview.json"
_PROV_DASHBOARDS = _MONITORING / "grafana" / "provisioning" / "dashboards" / "mxtac.yml"
_PROV_DATASOURCES = _MONITORING / "grafana" / "provisioning" / "datasources" / "prometheus.yml"
_PROMETHEUS_YML = _MONITORING / "prometheus.yml"

# Metrics that must be referenced in the dashboard PromQL targets
_REQUIRED_METRICS = [
    "http_request_duration_seconds_bucket",   # API latency histogram
    "http_requests_total",                     # API request rate / error rate
    "mxtac_websocket_connections",             # WebSocket gauge
    "mxtac_alerts_processed_total",            # Alert pipeline counter
    "mxtac_alerts_deduplicated_total",         # Dedup counter
    "mxtac_pipeline_latency_seconds_bucket",  # Pipeline latency histogram
    "mxtac_sigma_rules_loaded",               # Sigma rules gauge
    "mxtac_sigma_matches_total",              # Sigma matches counter
    "mxtac_rule_matches_total",              # Per-rule matches counter
    "mxtac_events_ingested_total",            # Event ingest counter
    "mxtac_connectors_active",                # Connectors gauge
]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def dashboard() -> dict:
    """Load and parse the Grafana dashboard JSON once for all tests."""
    raw = _DASHBOARD_JSON.read_text(encoding="utf-8")
    return json.loads(raw)


@pytest.fixture(scope="module")
def all_panels(dashboard: dict) -> list[dict]:
    """Return all panels in the dashboard (including row separators)."""
    return dashboard["panels"]


@pytest.fixture(scope="module")
def data_panels(all_panels: list[dict]) -> list[dict]:
    """Return only non-row panels (stat, timeseries, etc.)."""
    return [p for p in all_panels if p.get("type") != "row"]


@pytest.fixture(scope="module")
def all_targets(data_panels: list[dict]) -> list[dict]:
    """Return all PromQL targets across every data panel."""
    targets: list[dict] = []
    for panel in data_panels:
        targets.extend(panel.get("targets", []))
    return targets


# ---------------------------------------------------------------------------
# File existence and parse
# ---------------------------------------------------------------------------


def test_dashboard_json_file_exists() -> None:
    """mxtac-overview.json exists at the expected path."""
    assert _DASHBOARD_JSON.exists(), (
        f"Dashboard JSON not found: {_DASHBOARD_JSON}"
    )


def test_dashboard_json_is_valid_json() -> None:
    """mxtac-overview.json is valid JSON (no parse errors)."""
    raw = _DASHBOARD_JSON.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    assert isinstance(parsed, dict), "Dashboard JSON must be a JSON object"


# ---------------------------------------------------------------------------
# Top-level required fields
# ---------------------------------------------------------------------------


def test_dashboard_has_title(dashboard: dict) -> None:
    """Dashboard has a non-empty 'title' field."""
    assert "title" in dashboard
    assert dashboard["title"].strip(), "Dashboard title must not be empty"


def test_dashboard_has_uid(dashboard: dict) -> None:
    """Dashboard has a non-empty 'uid' field."""
    assert "uid" in dashboard
    assert dashboard["uid"].strip(), "Dashboard uid must not be empty"


def test_dashboard_uid_is_mxtac_overview(dashboard: dict) -> None:
    """Dashboard uid is 'mxtac-overview'."""
    assert dashboard["uid"] == "mxtac-overview", (
        f"Expected uid 'mxtac-overview'; got '{dashboard['uid']}'"
    )


def test_dashboard_has_panels(dashboard: dict) -> None:
    """Dashboard has a non-empty 'panels' list."""
    assert "panels" in dashboard
    assert isinstance(dashboard["panels"], list)
    assert len(dashboard["panels"]) > 0, "Dashboard must have at least one panel"


def test_dashboard_has_schema_version(dashboard: dict) -> None:
    """Dashboard has a 'schemaVersion' field."""
    assert "schemaVersion" in dashboard


def test_dashboard_schema_version_is_modern(dashboard: dict) -> None:
    """schemaVersion must be >= 36 (Grafana 9.x+ format)."""
    sv = dashboard["schemaVersion"]
    assert sv >= 36, f"schemaVersion {sv} < 36; dashboard may be too old for Grafana 9.x+"


def test_dashboard_has_time(dashboard: dict) -> None:
    """Dashboard has a 'time' field with 'from' and 'to' keys."""
    assert "time" in dashboard
    t = dashboard["time"]
    assert "from" in t, "time.from is missing"
    assert "to" in t, "time.to is missing"


def test_dashboard_has_templating(dashboard: dict) -> None:
    """Dashboard has a 'templating.list' with at least one variable."""
    assert "templating" in dashboard
    assert "list" in dashboard["templating"]
    assert len(dashboard["templating"]["list"]) >= 1, (
        "Dashboard must define at least one template variable"
    )


def test_dashboard_refresh_is_set(dashboard: dict) -> None:
    """Dashboard has a non-empty 'refresh' field."""
    assert "refresh" in dashboard
    assert dashboard["refresh"], "Dashboard refresh must not be empty"


def test_dashboard_tags_include_mxtac(dashboard: dict) -> None:
    """Dashboard tags must include 'mxtac'."""
    tags = dashboard.get("tags", [])
    assert "mxtac" in tags, f"Expected 'mxtac' in dashboard tags; got {tags}"


# ---------------------------------------------------------------------------
# Datasource template variable
# ---------------------------------------------------------------------------


def test_dashboard_has_datasource_variable(dashboard: dict) -> None:
    """Dashboard defines a 'datasource' template variable of type 'datasource'."""
    variables = dashboard["templating"]["list"]
    ds_vars = [v for v in variables if v.get("name") == "datasource"]
    assert len(ds_vars) >= 1, (
        "Dashboard must have a template variable named 'datasource'"
    )


def test_dashboard_datasource_variable_type_is_datasource(dashboard: dict) -> None:
    """The 'datasource' template variable must be of type 'datasource'."""
    variables = dashboard["templating"]["list"]
    ds_var = next((v for v in variables if v.get("name") == "datasource"), None)
    assert ds_var is not None
    assert ds_var.get("type") == "datasource", (
        f"Expected variable type 'datasource'; got '{ds_var.get('type')}'"
    )


def test_dashboard_datasource_variable_queries_prometheus(dashboard: dict) -> None:
    """The 'datasource' template variable queries the 'prometheus' data source type."""
    variables = dashboard["templating"]["list"]
    ds_var = next((v for v in variables if v.get("name") == "datasource"), None)
    assert ds_var is not None
    assert ds_var.get("query") == "prometheus", (
        f"Expected datasource variable query='prometheus'; got '{ds_var.get('query')}'"
    )


# ---------------------------------------------------------------------------
# Panel structure
# ---------------------------------------------------------------------------


def test_dashboard_has_row_panels(all_panels: list[dict]) -> None:
    """Dashboard contains at least one row separator panel for grouping."""
    rows = [p for p in all_panels if p.get("type") == "row"]
    assert len(rows) >= 1, "Dashboard must have at least one 'row' panel for grouping"


def test_dashboard_has_at_least_five_sections(all_panels: list[dict]) -> None:
    """Dashboard contains at least five row separator panels (major sections)."""
    rows = [p for p in all_panels if p.get("type") == "row"]
    assert len(rows) >= 5, (
        f"Expected at least 5 row separators (API Health, Alert Pipeline, "
        f"Sigma Detection, Event Ingestion, Infrastructure); got {len(rows)}"
    )


def test_all_panel_ids_are_unique(all_panels: list[dict]) -> None:
    """All panel IDs must be unique within the dashboard."""
    ids = [p["id"] for p in all_panels]
    assert len(ids) == len(set(ids)), (
        f"Duplicate panel IDs found: "
        f"{[i for i in set(ids) if ids.count(i) > 1]}"
    )


def test_all_panels_have_gridpos(all_panels: list[dict]) -> None:
    """Every panel must have a gridPos with h/w/x/y keys."""
    for panel in all_panels:
        gp = panel.get("gridPos", {})
        for key in ("h", "w", "x", "y"):
            assert key in gp, (
                f"Panel id={panel.get('id')} is missing gridPos.{key}"
            )


def test_data_panels_have_at_least_one_target(data_panels: list[dict]) -> None:
    """Every non-row panel must have at least one query target."""
    for panel in data_panels:
        targets = panel.get("targets", [])
        assert len(targets) >= 1, (
            f"Panel '{panel.get('title', panel.get('id'))}' has no query targets"
        )


def test_data_panels_reference_datasource_variable(data_panels: list[dict]) -> None:
    """Every non-row panel must use the ${datasource} template variable."""
    for panel in data_panels:
        ds = panel.get("datasource", {})
        # datasource can be specified at panel level or on individual targets
        if isinstance(ds, dict):
            uid = ds.get("uid", "")
        else:
            uid = str(ds)
        has_panel_ds = "${datasource}" in uid
        if not has_panel_ds:
            # Check if all targets specify it
            target_uids = [
                t.get("datasource", {}).get("uid", "") if isinstance(t.get("datasource"), dict) else ""
                for t in panel.get("targets", [])
            ]
            has_panel_ds = all("${datasource}" in u for u in target_uids)
        assert has_panel_ds, (
            f"Panel '{panel.get('title', panel.get('id'))}' must reference "
            f"${{datasource}} variable, not a hardcoded datasource"
        )


# ---------------------------------------------------------------------------
# PromQL target content
# ---------------------------------------------------------------------------


def test_all_targets_have_expr(all_targets: list[dict]) -> None:
    """Every query target must have a non-empty 'expr' field (PromQL expression)."""
    for target in all_targets:
        expr = target.get("expr", "")
        assert expr.strip(), (
            f"Target refId={target.get('refId')} has an empty 'expr' field"
        )


def test_all_targets_have_ref_id(all_targets: list[dict]) -> None:
    """Every query target must have a non-empty 'refId' field."""
    for target in all_targets:
        assert target.get("refId"), (
            f"Target is missing 'refId': {target}"
        )


def test_dashboard_covers_all_required_metrics(all_targets: list[dict]) -> None:
    """Every MxTac custom metric must appear in at least one dashboard PromQL target."""
    all_exprs = " ".join(t.get("expr", "") for t in all_targets)
    missing = [m for m in _REQUIRED_METRICS if m not in all_exprs]
    assert not missing, (
        f"The following metrics are not covered by any dashboard panel: {missing}"
    )


def test_dashboard_covers_api_latency(all_targets: list[dict]) -> None:
    """Dashboard includes a panel querying API latency (histogram_quantile)."""
    has_latency = any(
        "histogram_quantile" in t.get("expr", "") and "http_request_duration_seconds" in t.get("expr", "")
        for t in all_targets
    )
    assert has_latency, "Dashboard must have a panel showing API latency via histogram_quantile"


def test_dashboard_covers_sigma_match_rate_by_level(all_targets: list[dict]) -> None:
    """Dashboard includes a panel showing Sigma match rate broken down by level."""
    has_level = any(
        "mxtac_sigma_matches_total" in t.get("expr", "") and "level" in t.get("legendFormat", "")
        for t in all_targets
    )
    assert has_level, (
        "Dashboard must have a panel showing Sigma matches grouped by level "
        "(legendFormat should reference {{level}})"
    )


def test_dashboard_covers_event_ingest_rate_by_source(all_targets: list[dict]) -> None:
    """Dashboard includes a panel showing event ingest rate by source."""
    has_source = any(
        "mxtac_events_ingested_total" in t.get("expr", "") and "source" in t.get("legendFormat", "")
        for t in all_targets
    )
    assert has_source, (
        "Dashboard must have a panel showing event ingest rate by source "
        "(legendFormat should reference {{source}})"
    )


def test_dashboard_covers_top_rules_by_match_rate(all_targets: list[dict]) -> None:
    """Dashboard includes a panel showing top rules by match rate (topk query)."""
    has_topk = any(
        "mxtac_rule_matches_total" in t.get("expr", "") and "topk" in t.get("expr", "")
        for t in all_targets
    )
    assert has_topk, (
        "Dashboard must have a topk() panel showing top rules by match rate"
    )


# ---------------------------------------------------------------------------
# Grafana provisioning YAML — dashboards
# ---------------------------------------------------------------------------


def test_dashboard_provisioning_yaml_exists() -> None:
    """Grafana dashboard provisioning YAML exists."""
    assert _PROV_DASHBOARDS.exists(), f"Not found: {_PROV_DASHBOARDS}"


def test_dashboard_provisioning_yaml_is_valid() -> None:
    """Grafana dashboard provisioning YAML is parseable."""
    raw = _PROV_DASHBOARDS.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    assert isinstance(parsed, dict), "Dashboard provisioning YAML must be a mapping"


def test_dashboard_provisioning_has_providers(dashboard: dict) -> None:
    """Dashboard provisioning YAML defines at least one provider."""
    raw = _PROV_DASHBOARDS.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    assert "providers" in parsed, "Dashboard provisioning YAML must have a 'providers' key"
    assert len(parsed["providers"]) >= 1, "At least one dashboard provider must be defined"


def test_dashboard_provisioning_path_is_correct() -> None:
    """Dashboard provisioning provider path is '/etc/grafana/dashboards'."""
    raw = _PROV_DASHBOARDS.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    provider = parsed["providers"][0]
    path = provider.get("options", {}).get("path", "")
    assert path == "/etc/grafana/dashboards", (
        f"Dashboard provider path must be '/etc/grafana/dashboards'; got '{path}'"
    )


# ---------------------------------------------------------------------------
# Grafana provisioning YAML — datasources
# ---------------------------------------------------------------------------


def test_datasource_provisioning_yaml_exists() -> None:
    """Grafana datasource provisioning YAML exists."""
    assert _PROV_DATASOURCES.exists(), f"Not found: {_PROV_DATASOURCES}"


def test_datasource_provisioning_yaml_is_valid() -> None:
    """Grafana datasource provisioning YAML is parseable."""
    raw = _PROV_DATASOURCES.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    assert isinstance(parsed, dict), "Datasource provisioning YAML must be a mapping"


def test_datasource_provisioning_defines_prometheus() -> None:
    """Datasource provisioning YAML defines a Prometheus datasource."""
    raw = _PROV_DATASOURCES.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    datasources = parsed.get("datasources", [])
    prom_ds = [ds for ds in datasources if ds.get("type") == "prometheus"]
    assert len(prom_ds) >= 1, "Datasource provisioning must define at least one Prometheus datasource"


def test_datasource_provisioning_prometheus_is_default() -> None:
    """The Prometheus datasource must be marked as the default."""
    raw = _PROV_DATASOURCES.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    datasources = parsed.get("datasources", [])
    prom_ds = next((ds for ds in datasources if ds.get("type") == "prometheus"), None)
    assert prom_ds is not None
    assert prom_ds.get("isDefault") is True, (
        "The Prometheus datasource must be marked isDefault: true"
    )


def test_datasource_provisioning_url_points_to_prometheus() -> None:
    """The Prometheus datasource URL references the prometheus service."""
    raw = _PROV_DATASOURCES.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    datasources = parsed.get("datasources", [])
    prom_ds = next((ds for ds in datasources if ds.get("type") == "prometheus"), None)
    assert prom_ds is not None
    url = prom_ds.get("url", "")
    assert "prometheus" in url, (
        f"Prometheus datasource URL must reference 'prometheus' service; got '{url}'"
    )


# ---------------------------------------------------------------------------
# Prometheus scrape config
# ---------------------------------------------------------------------------


def test_prometheus_yml_exists() -> None:
    """Prometheus prometheus.yml config file exists."""
    assert _PROMETHEUS_YML.exists(), f"Not found: {_PROMETHEUS_YML}"


def test_prometheus_yml_is_valid_yaml() -> None:
    """prometheus.yml is valid YAML."""
    raw = _PROMETHEUS_YML.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    assert isinstance(parsed, dict), "prometheus.yml must be a YAML mapping"


def test_prometheus_yml_has_mxtac_backend_job() -> None:
    """prometheus.yml defines a 'mxtac-backend' scrape job."""
    raw = _PROMETHEUS_YML.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    jobs = [sc.get("job_name") for sc in parsed.get("scrape_configs", [])]
    assert "mxtac-backend" in jobs, (
        f"prometheus.yml must have a 'mxtac-backend' scrape job; found: {jobs}"
    )


def test_prometheus_yml_mxtac_backend_scrapes_port_8080() -> None:
    """The mxtac-backend scrape job targets port 8080."""
    raw = _PROMETHEUS_YML.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    backend_job = next(
        (sc for sc in parsed.get("scrape_configs", []) if sc.get("job_name") == "mxtac-backend"),
        None,
    )
    assert backend_job is not None
    targets = backend_job.get("static_configs", [{}])[0].get("targets", [])
    assert any("8080" in str(t) for t in targets), (
        f"mxtac-backend job must target port 8080; got targets: {targets}"
    )


def test_prometheus_yml_metrics_path_is_metrics() -> None:
    """The mxtac-backend scrape job uses /metrics as the metrics path."""
    raw = _PROMETHEUS_YML.read_text(encoding="utf-8")
    parsed = yaml.safe_load(raw)
    backend_job = next(
        (sc for sc in parsed.get("scrape_configs", []) if sc.get("job_name") == "mxtac-backend"),
        None,
    )
    assert backend_job is not None
    metrics_path = backend_job.get("metrics_path", "/metrics")
    assert metrics_path == "/metrics", (
        f"mxtac-backend metrics_path must be '/metrics'; got '{metrics_path}'"
    )
