"""Tests for feature 20.3 — Process supervisor Restart=always.

Validates the systemd service unit file at app/deploy/systemd/mxtac.service
to confirm that the restart policy, graceful shutdown, and security hardening
directives required for reliable headless autonomous operation are correct.

Feature 20.3 specification:
  - Restart=always     — restart on any exit (crash, OOM, clean exit, SIGTERM)
  - RestartSec >= 5 s  — delay before restart to avoid hammering broken deps
  - StartLimitBurst    — cap rapid restarts so systemd gives up on persistent faults
  - StartLimitIntervalSec — observation window for burst counting

Graceful shutdown (required to drain in-flight requests):
  - KillSignal=SIGTERM
  - KillMode=mixed
  - TimeoutStopSec >= 30 s  (matches k8s terminationGracePeriodSeconds)

Security hardening (least-privilege posture):
  - NoNewPrivileges=true
  - ProtectSystem=strict
  - ProtectHome=true
  - PrivateTmp=true
  - RestrictSUIDSGID=true
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path to the systemd service unit file under test
# ---------------------------------------------------------------------------

_SYSTEMD_DIR = (
    Path(__file__).parent.parent.parent.parent.parent  # app/
    / "deploy" / "systemd"
)
_SERVICE_FILE = _SYSTEMD_DIR / "mxtac.service"


# ---------------------------------------------------------------------------
# Parser helpers
# ---------------------------------------------------------------------------

def _parse_unit_file(path: Path) -> dict[str, dict[str, str]]:
    """Parse a systemd unit file into {section: {key: value}}.

    Handles:
    - Section headers: [Unit], [Service], [Install]
    - Key=Value pairs with backslash line-continuation
    - Comment lines (#) and blank lines are skipped
    - Duplicate keys: last value wins
    """
    sections: dict[str, dict[str, str]] = {}
    current: dict[str, str] = {}
    current_section = "__preamble__"
    sections[current_section] = current

    lines = path.read_text().splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.strip()

        if not line or line.startswith('#'):
            i += 1
            continue

        if line.startswith('[') and line.endswith(']'):
            current_section = line[1:-1]
            current = {}
            sections[current_section] = current
            i += 1
            continue

        if '=' in line:
            key, _, value = line.partition('=')
            key = key.strip()
            value_parts: list[str] = []
            while True:
                stripped = value.rstrip()
                if stripped.endswith('\\'):
                    value_parts.append(stripped[:-1].strip())
                    if i + 1 < len(lines):
                        i += 1
                        value = lines[i].strip()
                    else:
                        break
                else:
                    value_parts.append(stripped.strip())
                    break
            current[key] = ' '.join(v for v in value_parts if v)

        i += 1

    return sections


def _parse_duration_seconds(value: str) -> float:
    """Convert a systemd time-span string to seconds.

    Examples:
        '5s'   -> 5.0
        '30s'  -> 30.0
        '60s'  -> 60.0
        '2min' -> 120.0
    """
    value = value.strip()
    if value.endswith('min'):
        return float(value[:-3]) * 60
    if value.endswith('s'):
        return float(value[:-1])
    return float(value)


# ---------------------------------------------------------------------------
# Shared fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def service_sections() -> dict[str, dict[str, str]]:
    assert _SERVICE_FILE.exists(), (
        f"systemd service file not found: {_SERVICE_FILE}\n"
        "Expected at app/deploy/systemd/mxtac.service"
    )
    return _parse_unit_file(_SERVICE_FILE)


@pytest.fixture(scope="module")
def service(service_sections) -> dict[str, str]:
    return service_sections.get("Service", {})


@pytest.fixture(scope="module")
def unit(service_sections) -> dict[str, str]:
    return service_sections.get("Unit", {})


@pytest.fixture(scope="module")
def install(service_sections) -> dict[str, str]:
    return service_sections.get("Install", {})


# ---------------------------------------------------------------------------
# 1. File existence
# ---------------------------------------------------------------------------

class TestServiceFileExists:
    def test_service_file_present(self) -> None:
        """The systemd unit file must exist at the expected path."""
        assert _SERVICE_FILE.exists(), (
            f"Service file not found: {_SERVICE_FILE}"
        )

    def test_service_file_not_empty(self) -> None:
        """The service file must have non-zero content."""
        assert _SERVICE_FILE.stat().st_size > 0

    def test_service_file_has_service_section(self, service_sections) -> None:
        """The file must contain a [Service] section."""
        assert "Service" in service_sections, (
            "No [Service] section found in mxtac.service"
        )


# ---------------------------------------------------------------------------
# 2. Restart policy — feature 20.3 core
# ---------------------------------------------------------------------------

class TestRestartPolicy:
    """Feature 20.3: Process supervisor Restart=always.

    The service must restart automatically on any exit condition so that
    MxTac operates without manual intervention (headless / autonomous mode).
    """

    def test_restart_always(self, service: dict) -> None:
        """Restart=always ensures restart on crash, OOM, clean exit, or signal.

        'always' is more aggressive than 'on-failure': it also restarts after
        a clean exit (exit code 0), which matters because a misconfigured
        dependency can cause a graceful exit that should still trigger recovery.
        """
        restart = service.get("Restart", "")
        assert restart == "always", (
            f"Expected Restart=always, got Restart={restart!r}. "
            "Restart=always is required for autonomous headless operation."
        )

    def test_restart_sec_present(self, service: dict) -> None:
        """RestartSec must be set to insert a delay before each restart attempt."""
        assert "RestartSec" in service, (
            "RestartSec is not set. Without a delay, rapid crash-restart loops "
            "can hammer a broken dependency (database, Valkey) and exhaust "
            "connection pools before the root cause can be diagnosed."
        )

    def test_restart_sec_minimum_5s(self, service: dict) -> None:
        """RestartSec >= 5 s prevents restart storms on transient dependency failures."""
        restart_sec = _parse_duration_seconds(service["RestartSec"])
        assert restart_sec >= 5, (
            f"RestartSec={service['RestartSec']!r} is {restart_sec} s, need >= 5 s. "
            "A too-short delay causes rapid crash-restart loops that can trigger OOM "
            "or exhaust database connection pools before the dependency recovers."
        )

    def test_start_limit_burst_present(self, service: dict) -> None:
        """StartLimitBurst must cap the number of rapid restart attempts.

        Without a burst limit, systemd restarts the service indefinitely even
        when the root cause cannot be fixed at runtime (e.g. bad DB credentials).
        The operator needs systemd to give up and alert, not loop forever.
        """
        assert "StartLimitBurst" in service, (
            "StartLimitBurst is not set. Without a burst cap, systemd will "
            "restart indefinitely on persistent faults with no operator alert."
        )

    def test_start_limit_burst_in_reasonable_range(self, service: dict) -> None:
        """StartLimitBurst must be between 3 and 10 (inclusive).

        Too low (< 3): legitimate cold-start restarts (DB not yet ready) fail.
        Too high (> 10): masks cascading failures; alerting is delayed.
        """
        burst = int(service["StartLimitBurst"])
        assert 3 <= burst <= 10, (
            f"StartLimitBurst={burst} is outside [3, 10]. "
            "This range balances recovery from transient faults vs masking persistent ones."
        )

    def test_start_limit_interval_present(self, service: dict) -> None:
        """StartLimitIntervalSec must define the burst-counting observation window."""
        assert "StartLimitIntervalSec" in service, (
            "StartLimitIntervalSec is not set. "
            "StartLimitBurst has no effect without a time window."
        )

    def test_start_limit_interval_minimum_30s(self, service: dict) -> None:
        """StartLimitIntervalSec >= 30 s — window long enough to detect flapping."""
        interval = _parse_duration_seconds(service["StartLimitIntervalSec"])
        assert interval >= 30, (
            f"StartLimitIntervalSec={service['StartLimitIntervalSec']!r} is {interval} s, "
            "need >= 30 s. A very short window lets a flapping service escape the burst cap."
        )


# ---------------------------------------------------------------------------
# 3. Graceful shutdown
# ---------------------------------------------------------------------------

class TestGracefulShutdown:
    """Uvicorn must receive SIGTERM and have time to drain in-flight connections.

    The drain timeout must match the Kubernetes terminationGracePeriodSeconds
    (30 s) so that systemd and k8s agree on how long the process gets to stop.
    """

    def test_kill_signal_is_sigterm(self, service: dict) -> None:
        """KillSignal=SIGTERM triggers Uvicorn's graceful connection draining."""
        kill_signal = service.get("KillSignal", "")
        assert kill_signal == "SIGTERM", (
            f"Expected KillSignal=SIGTERM, got {kill_signal!r}. "
            "SIGTERM is the standard graceful-shutdown signal for ASGI servers."
        )

    def test_kill_mode_is_mixed(self, service: dict) -> None:
        """KillMode=mixed sends SIGTERM to the main process then SIGKILL to stragglers.

        'mixed' ensures that any child processes spawned by Uvicorn are also
        cleaned up after the drain timeout expires, preventing zombie workers.
        """
        kill_mode = service.get("KillMode", "")
        assert kill_mode == "mixed", (
            f"Expected KillMode=mixed, got {kill_mode!r}. "
            "'mixed' is required to clean up Uvicorn child workers after drain."
        )

    def test_timeout_stop_sec_present(self, service: dict) -> None:
        """TimeoutStopSec must be explicitly set to control the drain period."""
        assert "TimeoutStopSec" in service, (
            "TimeoutStopSec is not set. systemd will use its default (90 s), "
            "which does not match Kubernetes terminationGracePeriodSeconds=30."
        )

    def test_timeout_stop_sec_minimum_30s(self, service: dict) -> None:
        """TimeoutStopSec >= 30 s matches Kubernetes terminationGracePeriodSeconds."""
        timeout = _parse_duration_seconds(service["TimeoutStopSec"])
        assert timeout >= 30, (
            f"TimeoutStopSec={service['TimeoutStopSec']!r} is {timeout} s, need >= 30 s. "
            "Uvicorn needs at least 30 s to drain in-flight connections gracefully."
        )


# ---------------------------------------------------------------------------
# 4. Security hardening
# ---------------------------------------------------------------------------

class TestSecurityHardening:
    """Verify least-privilege system access for the mxtac service process."""

    def test_no_new_privileges(self, service: dict) -> None:
        """NoNewPrivileges=true prevents privilege escalation via setuid binaries."""
        assert service.get("NoNewPrivileges") == "true", (
            "NoNewPrivileges must be 'true'. Without it, the process can gain "
            "additional privileges by executing setuid binaries."
        )

    def test_protect_system_strict(self, service: dict) -> None:
        """ProtectSystem=strict mounts /usr, /boot, /etc read-only."""
        assert service.get("ProtectSystem") == "strict", (
            "ProtectSystem must be 'strict' for a read-only filesystem posture. "
            "'full' only protects /usr and /boot; 'strict' also covers /etc."
        )

    def test_protect_home(self, service: dict) -> None:
        """ProtectHome=true prevents access to /home, /root, /run/user."""
        assert service.get("ProtectHome") == "true"

    def test_private_tmp(self, service: dict) -> None:
        """PrivateTmp=true gives the service a private /tmp namespace.

        Prevents temp-file disclosure or collision between services sharing
        the same host.
        """
        assert service.get("PrivateTmp") == "true"

    def test_restrict_suid_sgid(self, service: dict) -> None:
        """RestrictSUIDSGID=true prevents the process from acquiring SUID/SGID bits."""
        assert service.get("RestrictSUIDSGID") == "true"


# ---------------------------------------------------------------------------
# 5. Service identity
# ---------------------------------------------------------------------------

class TestServiceIdentity:
    """Verify the service runs as the unprivileged mxtac system user."""

    def test_user_is_mxtac(self, service: dict) -> None:
        """Service must run as 'mxtac', not root."""
        user = service.get("User", "")
        assert user == "mxtac", (
            f"Expected User=mxtac, got User={user!r}. "
            "Running as root violates the principle of least privilege."
        )

    def test_type_exec(self, service: dict) -> None:
        """Type=exec — single process, no daemonization; systemd tracks the main PID."""
        service_type = service.get("Type", "")
        assert service_type == "exec", (
            f"Expected Type=exec, got Type={service_type!r}. "
            "'exec' is the correct type for Uvicorn (no double-fork daemonization)."
        )

    def test_exec_start_invokes_uvicorn(self, service: dict) -> None:
        """ExecStart must launch Uvicorn as the ASGI server."""
        exec_start = service.get("ExecStart", "")
        assert "uvicorn" in exec_start.lower(), (
            f"ExecStart does not contain 'uvicorn': {exec_start!r}"
        )

    def test_exec_start_pre_runs_alembic(self, service: dict) -> None:
        """ExecStartPre must run Alembic migrations before the service starts.

        Running migrations as a pre-start hook ensures the schema is always
        current without requiring a separate deployment step.
        """
        exec_start_pre = service.get("ExecStartPre", "")
        assert "alembic" in exec_start_pre.lower(), (
            f"ExecStartPre does not contain 'alembic': {exec_start_pre!r}"
        )

    def test_exec_start_single_worker(self, service: dict) -> None:
        """ExecStart must use a single Uvicorn worker.

        Horizontal scaling is handled by HAProxy / k3s. Multiple workers in a
        single process complicate the WebSocket broadcaster and stateless design.
        """
        exec_start = service.get("ExecStart", "")
        match = re.search(r"--workers\s+(\d+)", exec_start)
        assert match, f"--workers flag not found in ExecStart: {exec_start!r}"
        workers = int(match.group(1))
        assert workers == 1, (
            f"--workers={workers}: the service file must use a single worker. "
            "Scale horizontally via HAProxy or Kubernetes replicas instead."
        )


# ---------------------------------------------------------------------------
# 6. [Unit] dependencies
# ---------------------------------------------------------------------------

class TestUnitDependencies:
    """Verify that the unit declares correct systemd ordering."""

    def test_after_network_online(self, unit: dict) -> None:
        """Service must start after network-online.target.

        Without this ordering, the process may start before network interfaces
        are up, causing database and Valkey connections to fail at startup.
        """
        after = unit.get("After", "")
        assert "network-online.target" in after, (
            f"After= does not include 'network-online.target': {after!r}"
        )

    def test_wants_network_online(self, unit: dict) -> None:
        """Wants=network-online.target pulls in the network-online dependency."""
        wants = unit.get("Wants", "")
        assert "network-online.target" in wants, (
            f"Wants= does not include 'network-online.target': {wants!r}"
        )


# ---------------------------------------------------------------------------
# 7. [Install] section
# ---------------------------------------------------------------------------

class TestInstallSection:
    """Verify the service is installed for the correct systemd target."""

    def test_wanted_by_multi_user_target(self, install: dict) -> None:
        """WantedBy=multi-user.target enables auto-start in multi-user mode.

        This causes the service to be enabled when the system boots to runlevel
        3 (multi-user, no GUI), which is standard for servers.
        """
        wanted_by = install.get("WantedBy", "")
        assert "multi-user.target" in wanted_by, (
            f"WantedBy= does not include 'multi-user.target': {wanted_by!r}. "
            "Without this, 'systemctl enable mxtac' will not auto-start the service."
        )
