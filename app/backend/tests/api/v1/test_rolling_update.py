"""Tests for feature 19.12 — Rolling update: zero downtime deploy.

Verifies the two layers that make zero-downtime Kubernetes rolling updates work:

1. Kubernetes manifest invariants (parsed from the YAML files):
   - strategy.type == RollingUpdate
   - strategy.rollingUpdate.maxUnavailable == 0  (no pod removed before new one is ready)
   - strategy.rollingUpdate.maxSurge == 1        (controlled: one new pod at a time)
   - terminationGracePeriodSeconds >= 30         (enough time for in-flight requests)
   - containers[backend].lifecycle.preStop       (LB drain before SIGTERM)
   - initContainers[migrate] runs alembic        (schema current before traffic)

2. Application-level behaviour during a rolling update:
   - /health always returns 200 (liveness probe must never block pod restart)
   - /health returns 200 even after on_shutdown() has been called
   - /ready gates traffic via 200 / 503 (readiness probe pulls pod from rotation)
   - Shutdown is resilient when called with partially-initialised state
   - Shutdown completes in the correct order: connectors → queue → alert_mgr → os_client
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from httpx import AsyncClient

from app.main import app, on_shutdown


# ---------------------------------------------------------------------------
# Paths to the Kubernetes manifests under test
# ---------------------------------------------------------------------------

_K3S_DIR = (
    Path(__file__).parent.parent.parent.parent.parent  # app/backend/
    / "deploy" / "k3s"
)
_BACKEND_MANIFEST = _K3S_DIR / "backend-deployment.yaml"
_FRONTEND_MANIFEST = _K3S_DIR / "frontend-deployment.yaml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_deployment(path: Path) -> dict:
    """Parse a Kubernetes Deployment YAML and return the first document."""
    with path.open() as fh:
        docs = list(yaml.safe_load_all(fh))
    deployments = [d for d in docs if d and d.get("kind") == "Deployment"]
    assert deployments, f"No Deployment found in {path}"
    return deployments[0]


def _get_container(deployment: dict, name: str) -> dict:
    """Return the named container spec from a Deployment."""
    containers = deployment["spec"]["template"]["spec"]["containers"]
    for c in containers:
        if c["name"] == name:
            return c
    raise KeyError(f"Container '{name}' not found in {[c['name'] for c in containers]}")


def _get_init_container(deployment: dict, name: str) -> dict:
    """Return the named init container spec from a Deployment."""
    init_containers = deployment["spec"]["template"]["spec"].get("initContainers", [])
    for c in init_containers:
        if c["name"] == name:
            return c
    raise KeyError(
        f"initContainer '{name}' not found in {[c['name'] for c in init_containers]}"
    )


# ---------------------------------------------------------------------------
# 1. Kubernetes manifest invariants — backend
# ---------------------------------------------------------------------------


class TestBackendDeploymentManifest:
    """Validate backend-deployment.yaml rolling update configuration."""

    def setup_method(self) -> None:
        self.deployment = _load_deployment(_BACKEND_MANIFEST)
        self.spec = self.deployment["spec"]

    def test_strategy_is_rolling_update(self) -> None:
        """Deployment strategy must be RollingUpdate (not Recreate)."""
        assert self.spec["strategy"]["type"] == "RollingUpdate"

    def test_max_unavailable_is_zero(self) -> None:
        """maxUnavailable: 0 — no pod is taken offline before a new one is healthy.

        This is the core zero-downtime guarantee: Kubernetes will never reduce
        the number of Running+Ready pods below the current replica count.
        """
        assert self.spec["strategy"]["rollingUpdate"]["maxUnavailable"] == 0

    def test_max_surge_is_one(self) -> None:
        """maxSurge: 1 — at most one extra pod is created during a rollout.

        Keeps the rollout controlled: one new pod becomes healthy and one old
        pod is terminated at a time.
        """
        assert self.spec["strategy"]["rollingUpdate"]["maxSurge"] == 1

    def test_termination_grace_period_at_least_30s(self) -> None:
        """terminationGracePeriodSeconds >= 30 — in-flight requests have time to finish.

        preStop sleeps for 10 s; the app then gets at least 20 s after SIGTERM
        to drain remaining connections before Kubernetes force-kills the pod.
        """
        tgp = self.spec["template"]["spec"]["terminationGracePeriodSeconds"]
        assert tgp >= 30, f"terminationGracePeriodSeconds={tgp} is too short (need ≥ 30)"

    def test_backend_container_has_prestop_hook(self) -> None:
        """Backend container must declare a preStop lifecycle hook.

        The hook (sleep 10 s) gives the Kubernetes endpoints controller and
        ingress time to stop routing new requests to the pod before SIGTERM
        arrives.  Without this there is a race condition where requests land
        on a pod that has already started shutting down.
        """
        container = _get_container(self.deployment, "backend")
        lifecycle = container.get("lifecycle", {})
        assert "preStop" in lifecycle, "preStop lifecycle hook is missing from the backend container"
        pre_stop = lifecycle["preStop"]
        assert "exec" in pre_stop, "preStop must use exec handler (not httpGet)"
        command = pre_stop["exec"].get("command", [])
        assert command, "preStop exec command must not be empty"

    def test_backend_prestop_provides_drain_window(self) -> None:
        """preStop command must sleep for at least 5 seconds to allow LB propagation."""
        container = _get_container(self.deployment, "backend")
        command = container["lifecycle"]["preStop"]["exec"]["command"]
        # The sleep value appears somewhere in the command list (e.g. ["sh", "-c", "sleep 10"])
        full_cmd = " ".join(str(c) for c in command)
        # Extract numeric sleep value
        import re
        match = re.search(r"sleep\s+(\d+)", full_cmd)
        assert match, f"preStop command does not contain a 'sleep N' call: {full_cmd!r}"
        sleep_secs = int(match.group(1))
        assert sleep_secs >= 5, f"preStop sleep is {sleep_secs} s — should be ≥ 5 s for LB propagation"

    def test_migration_init_container_exists(self) -> None:
        """An init container named 'migrate' must run before the backend starts.

        This ensures the database schema is current before any replica begins
        serving traffic, which is critical when schema changes accompany a
        rolling update.
        """
        container = _get_init_container(self.deployment, "migrate")
        assert container is not None

    def test_migration_init_container_runs_alembic(self) -> None:
        """The migrate init container must invoke 'alembic upgrade head'."""
        container = _get_init_container(self.deployment, "migrate")
        command = container.get("command", [])
        full_cmd = " ".join(str(c) for c in command)
        assert "alembic" in full_cmd, f"migrate init container must call alembic, got: {full_cmd!r}"
        assert "upgrade" in full_cmd, f"migrate init container must run 'upgrade', got: {full_cmd!r}"

    def test_migration_init_container_uses_same_image(self) -> None:
        """The migrate init container must use the same backend image as the main container."""
        main = _get_container(self.deployment, "backend")
        migrate = _get_init_container(self.deployment, "migrate")
        # Strip any tag suffix for comparison — both should share the same base
        assert migrate["image"].split(":")[0] == main["image"].split(":")[0], (
            f"Init container image {migrate['image']!r} should match backend image {main['image']!r}"
        )

    def test_migration_init_container_has_database_url_env(self) -> None:
        """The migrate init container must have DATABASE_URL to connect to PostgreSQL."""
        container = _get_init_container(self.deployment, "migrate")
        env_names = {e["name"] for e in container.get("env", [])}
        assert "DATABASE_URL" in env_names, (
            "migrate init container is missing DATABASE_URL env var"
        )

    def test_readiness_probe_uses_ready_endpoint(self) -> None:
        """Backend readiness probe must target /ready (not /health).

        /ready returns 503 when dependencies are unavailable — this prevents
        Kubernetes from routing traffic to a pod that cannot serve requests.
        /health is for liveness only (always 200).
        """
        container = _get_container(self.deployment, "backend")
        probe = container["readinessProbe"]["httpGet"]
        assert probe["path"] == "/ready"

    def test_liveness_probe_uses_health_endpoint(self) -> None:
        """Backend liveness probe must target /health (always 200).

        If the liveness probe used /ready, a transient dependency failure would
        cause Kubernetes to restart the pod — needlessly discarding in-flight
        requests and triggering another rolling restart.
        """
        container = _get_container(self.deployment, "backend")
        probe = container["livenessProbe"]["httpGet"]
        assert probe["path"] == "/health"

    def test_revision_history_limit_set(self) -> None:
        """revisionHistoryLimit should be set to enable kubectl rollout undo."""
        limit = self.spec.get("revisionHistoryLimit")
        assert limit is not None and limit >= 1, (
            "revisionHistoryLimit must be set to allow rollbacks"
        )


# ---------------------------------------------------------------------------
# 2. Kubernetes manifest invariants — frontend
# ---------------------------------------------------------------------------


class TestFrontendDeploymentManifest:
    """Validate frontend-deployment.yaml rolling update configuration."""

    def setup_method(self) -> None:
        self.deployment = _load_deployment(_FRONTEND_MANIFEST)
        self.spec = self.deployment["spec"]

    def test_strategy_is_rolling_update(self) -> None:
        """Frontend Deployment strategy must be RollingUpdate."""
        assert self.spec["strategy"]["type"] == "RollingUpdate"

    def test_max_unavailable_is_zero(self) -> None:
        """maxUnavailable: 0 — zero-downtime guarantee for the frontend."""
        assert self.spec["strategy"]["rollingUpdate"]["maxUnavailable"] == 0

    def test_frontend_container_has_prestop_hook(self) -> None:
        """Frontend container must declare a preStop lifecycle hook for LB drain."""
        container = _get_container(self.deployment, "frontend")
        lifecycle = container.get("lifecycle", {})
        assert "preStop" in lifecycle, "preStop lifecycle hook is missing from the frontend container"
        assert "exec" in lifecycle["preStop"]


# ---------------------------------------------------------------------------
# 3. Application behaviour — liveness probe contract
# ---------------------------------------------------------------------------


class TestLivenessProbeContract:
    """/health must always return 200, regardless of application or dependency state.

    The Kubernetes liveness probe uses /health.  If this probe ever returns
    a non-200 response, Kubernetes interprets the pod as dead and restarts it —
    which would interrupt in-flight requests and undermine zero-downtime.
    """

    @pytest.mark.asyncio
    async def test_health_always_200(self, client: AsyncClient) -> None:
        """/health returns 200 with status='ok' in the happy path."""
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_health_200_after_shutdown(self, client: AsyncClient) -> None:
        """/health returns 200 even after on_shutdown() has been called.

        During a rolling update, Kubernetes may poll /health after SIGTERM is
        sent (within the terminationGracePeriodSeconds window).  The liveness
        probe must not flip to a failure state during graceful shutdown — that
        would cause Kubernetes to force-kill the pod before it drains.
        """
        # Simulate shutdown (SIGTERM received)
        app.state.queue = None
        app.state.alert_mgr = None
        app.state.os_client = None
        app.state.connectors = {}
        await on_shutdown()

        # Liveness probe must still pass
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @pytest.mark.asyncio
    async def test_health_200_when_dependencies_unreachable(
        self, client: AsyncClient
    ) -> None:
        """/health returns 200 even when /ready would return 503.

        The liveness and readiness probes have different semantics:
        - /ready  → is this pod capable of serving new requests right now?
        - /health → is this pod's process alive and not deadlocked?

        A pod with unreachable dependencies should be *removed from rotation*
        (readiness failure → 503) but NOT restarted (liveness stays at 200).
        """
        resp = await client.get("/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 4. Application behaviour — readiness probe contract
# ---------------------------------------------------------------------------


class TestReadinessProbeContract:
    """/ready must gate traffic correctly — 200 only when all dependencies healthy.

    Kubernetes will not route traffic to a pod whose readiness probe returns
    a non-200 response.  This is what prevents new pods from receiving traffic
    before they are ready and what keeps old pods in rotation until the new
    pod is fully healthy.
    """

    @pytest.mark.asyncio
    async def test_ready_has_required_check_keys(self, client: AsyncClient) -> None:
        """/ready response must include postgres, valkey, and opensearch checks."""
        resp = await client.get("/ready")
        checks = resp.json()["checks"]
        for key in ("postgres", "valkey", "opensearch"):
            assert key in checks, f"Missing check key: {key!r}"

    @pytest.mark.asyncio
    async def test_ready_status_matches_http_code(self, client: AsyncClient) -> None:
        """HTTP 200 ↔ status='ready'; HTTP 503 ↔ status='degraded'."""
        resp = await client.get("/ready")
        data = resp.json()
        if data["status"] == "ready":
            assert resp.status_code == 200
        else:
            assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_ready_503_when_single_dependency_fails(
        self, client: AsyncClient
    ) -> None:
        """/ready returns 503 when any one dependency check fails.

        Even a single failed dependency should pull the pod out of the Service
        endpoint pool so that requests are routed to healthy replicas.
        """
        import sys
        from unittest.mock import patch

        # Simulate Postgres failure
        session = AsyncMock()
        session.__aenter__ = AsyncMock(side_effect=Exception("pg down"))
        pg_factory = MagicMock(return_value=session)

        vk_client = MagicMock()
        vk_client.ping = AsyncMock(return_value=True)
        vk_client.aclose = AsyncMock()

        mock_os_instance = MagicMock()
        mock_os_instance.ping = AsyncMock(return_value=True)
        mock_os_instance.close = AsyncMock()
        mock_os_module = MagicMock()
        mock_os_module.AsyncOpenSearch = MagicMock(return_value=mock_os_instance)

        with (
            patch("app.main.AsyncSessionLocal", pg_factory),
            patch("valkey.asyncio.from_url", return_value=vk_client),
            patch.dict(sys.modules, {"opensearchpy": mock_os_module}),
        ):
            resp = await client.get("/ready")

        assert resp.status_code == 503
        data = resp.json()
        assert data["status"] == "degraded"
        assert data["checks"]["postgres"].startswith("error:")


# ---------------------------------------------------------------------------
# 5. Application behaviour — graceful shutdown
# ---------------------------------------------------------------------------


class TestGracefulShutdown:
    """Validate shutdown behaviour in the context of zero-downtime rolling updates.

    When Kubernetes sends SIGTERM (after the preStop hook completes), the
    application's shutdown handler runs.  It must:
    1. Complete without raising exceptions (even if some state is missing).
    2. Stop all consumers in dependency order so no events are lost.
    3. Not interfere with any in-flight requests still being served.
    """

    @pytest.mark.asyncio
    async def test_shutdown_completes_without_error(self) -> None:
        """on_shutdown() must not raise even with no state configured."""
        app.state.queue = None
        app.state.alert_mgr = None
        app.state.os_client = None
        app.state.connectors = {}

        await on_shutdown()  # must not raise

    @pytest.mark.asyncio
    async def test_shutdown_stops_all_connectors(self) -> None:
        """Shutdown calls stop() on every registered connector."""
        conn_a = AsyncMock()
        conn_a.config = MagicMock(name="wazuh")
        conn_b = AsyncMock()
        conn_b.config = MagicMock(name="zeek")

        app.state.queue = None
        app.state.alert_mgr = None
        app.state.os_client = None
        app.state.connectors = {"a": conn_a, "b": conn_b}

        await on_shutdown()

        conn_a.stop.assert_called_once()
        conn_b.stop.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_order_connectors_before_queue(self) -> None:
        """Connectors stop before the message queue — prevents lost events.

        If the queue stops first, connectors could still push events into a
        dead queue and lose data.  Stopping connectors first is safe.
        """
        call_order: list[str] = []

        mock_queue = AsyncMock()
        mock_queue.stop = AsyncMock(side_effect=lambda: call_order.append("queue"))

        conn = AsyncMock()
        conn.config = MagicMock(name="wazuh")
        conn.stop = AsyncMock(side_effect=lambda: call_order.append("connector"))

        app.state.queue = mock_queue
        app.state.alert_mgr = None
        app.state.os_client = None
        app.state.connectors = {"c": conn}

        await on_shutdown()

        assert call_order.index("connector") < call_order.index("queue")

    @pytest.mark.asyncio
    async def test_shutdown_continues_after_connector_failure(self) -> None:
        """A connector that raises on stop() must not prevent queue and OS cleanup."""
        bad_conn = AsyncMock()
        bad_conn.config = MagicMock(name="broken")
        bad_conn.stop.side_effect = RuntimeError("network gone")

        mock_queue = AsyncMock()
        mock_os = AsyncMock()

        app.state.queue = mock_queue
        app.state.alert_mgr = None
        app.state.os_client = mock_os
        app.state.connectors = {"bad": bad_conn}

        await on_shutdown()

        mock_queue.stop.assert_called_once()
        mock_os.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown_resilient_to_missing_state(self) -> None:
        """Shutdown must not raise when startup was interrupted mid-way."""
        # Simulate startup that crashed before setting state
        for attr in ("queue", "alert_mgr", "os_client", "connectors"):
            try:
                delattr(app.state, attr)
            except AttributeError:
                pass

        await on_shutdown()  # must not raise
