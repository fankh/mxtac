"""Tests for app.db.seed — idempotent database seeder.

Feature 18.9 — Seed data on first startup (idempotent)

Approach:
  - All session interactions are mocked (no live DB needed)
  - session.scalar drives the idempotency check (user count)
  - session.add_all and session.commit are mocked to verify calls
  - Two scenarios: empty DB (seed runs) and populated DB (seed skips)

Coverage:
  - seed_database(): skips when user_count > 0
  - seed_database(): runs when user_count == 0
  - seed_database(): runs when user_count is None (empty scalar result)
  - seed_database(): calls session.add_all for users, detections, connectors, rules, incidents
  - seed_database(): calls session.commit exactly once after all adds
  - seed_database(): adds exactly 4 users
  - seed_database(): adds exactly 11 detections
  - seed_database(): adds exactly 3 connectors
  - seed_database(): adds exactly 4 rules
  - seed_database(): adds exactly 3 incidents
  - seed_database(): all users have hashed passwords (not plaintext)
  - seed_database(): all rules have non-empty YAML content
  - seed_database(): all incidents link to existing detection IDs
  - seed_database(): idempotent — safe to call twice on populated DB
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from app.db.seed import seed_database
from app.models.connector import Connector
from app.models.detection import Detection
from app.models.incident import Incident
from app.models.rule import Rule
from app.models.user import User


# ---------------------------------------------------------------------------
# Bcrypt compat shim — passlib 1.7.4 + bcrypt >= 4 incompatibility
#
# passlib's detect_wrap_bug sends a >72-byte test password to bcrypt during
# backend init; bcrypt >= 4 now raises ValueError for such inputs.  The shim
# truncates the oversized test password so passlib initialises correctly.
# ---------------------------------------------------------------------------

import bcrypt as _raw_bcrypt  # noqa: E402

_ORIG_HASHPW = _raw_bcrypt.hashpw


def _compat_hashpw(password: bytes, salt: bytes) -> bytes:
    if len(password) > 72:
        password = password[:72]
    return _ORIG_HASHPW(password, salt)


@pytest.fixture(scope="session", autouse=True)
def _patch_bcrypt_compat():
    if not hasattr(_raw_bcrypt, "__about__"):
        class _About:
            __version__ = _raw_bcrypt.__version__
        _raw_bcrypt.__about__ = _About  # type: ignore[attr-defined]
    _raw_bcrypt.hashpw = _compat_hashpw  # type: ignore[assignment]
    yield
    _raw_bcrypt.hashpw = _ORIG_HASHPW  # type: ignore[assignment]
    if hasattr(_raw_bcrypt, "__about__"):
        del _raw_bcrypt.__about__  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Session factory helper
# ---------------------------------------------------------------------------


def _make_session(user_count: int | None = 0) -> MagicMock:
    """Sync MagicMock for AsyncSession with async methods patched."""
    session = MagicMock()
    session.scalar = AsyncMock(return_value=user_count)
    session.add_all = MagicMock()
    session.commit = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# Idempotency — skip when already seeded
# ---------------------------------------------------------------------------


class TestSeedIdempotency:
    """seed_database() skips when users already exist."""

    @pytest.mark.asyncio
    async def test_skips_when_user_count_is_positive(self) -> None:
        session = _make_session(user_count=4)

        await seed_database(session)

        session.add_all.assert_not_called()
        session.commit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_skips_when_user_count_is_one(self) -> None:
        session = _make_session(user_count=1)

        await seed_database(session)

        session.add_all.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_when_user_count_is_large(self) -> None:
        session = _make_session(user_count=100)

        await seed_database(session)

        session.commit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_runs_when_user_count_is_zero(self) -> None:
        session = _make_session(user_count=0)

        await seed_database(session)

        session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_runs_when_user_count_is_none(self) -> None:
        """None result from scalar (new empty table) — seed must run."""
        session = _make_session(user_count=None)

        await seed_database(session)

        session.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_scalar_checked_exactly_once(self) -> None:
        session = _make_session(user_count=0)

        await seed_database(session)

        session.scalar.assert_awaited_once()


# ---------------------------------------------------------------------------
# Entity counts
# ---------------------------------------------------------------------------


class TestSeedEntityCounts:
    """seed_database() inserts the expected number of each entity type."""

    @pytest.fixture
    def captured_calls(self) -> list[list]:
        """Returns a list that accumulates the items passed to add_all calls."""
        return []

    @pytest.mark.asyncio
    async def test_adds_four_users(self) -> None:
        session = _make_session(user_count=0)
        added: list[list] = []
        session.add_all.side_effect = lambda items: added.append(list(items))

        await seed_database(session)

        users = [item for batch in added for item in batch if isinstance(item, User)]
        assert len(users) == 4

    @pytest.mark.asyncio
    async def test_adds_eleven_detections(self) -> None:
        session = _make_session(user_count=0)
        added: list[list] = []
        session.add_all.side_effect = lambda items: added.append(list(items))

        await seed_database(session)

        detections = [item for batch in added for item in batch if isinstance(item, Detection)]
        assert len(detections) == 11

    @pytest.mark.asyncio
    async def test_adds_three_connectors(self) -> None:
        session = _make_session(user_count=0)
        added: list[list] = []
        session.add_all.side_effect = lambda items: added.append(list(items))

        await seed_database(session)

        connectors = [item for batch in added for item in batch if isinstance(item, Connector)]
        assert len(connectors) == 3

    @pytest.mark.asyncio
    async def test_adds_four_rules(self) -> None:
        session = _make_session(user_count=0)
        added: list[list] = []
        session.add_all.side_effect = lambda items: added.append(list(items))

        await seed_database(session)

        rules = [item for batch in added for item in batch if isinstance(item, Rule)]
        assert len(rules) == 4

    @pytest.mark.asyncio
    async def test_adds_three_incidents(self) -> None:
        session = _make_session(user_count=0)
        added: list[list] = []
        session.add_all.side_effect = lambda items: added.append(list(items))

        await seed_database(session)

        incidents = [item for batch in added for item in batch if isinstance(item, Incident)]
        assert len(incidents) == 3

    @pytest.mark.asyncio
    async def test_add_all_called_five_times(self) -> None:
        """One add_all call per entity group: users, detections, connectors, rules, incidents."""
        session = _make_session(user_count=0)

        await seed_database(session)

        assert session.add_all.call_count == 5

    @pytest.mark.asyncio
    async def test_commit_called_exactly_once(self) -> None:
        session = _make_session(user_count=0)

        await seed_database(session)

        session.commit.assert_awaited_once()


# ---------------------------------------------------------------------------
# User data correctness
# ---------------------------------------------------------------------------


class TestSeedUsers:
    """Verifies seeded user data is correct."""

    @pytest.fixture
    async def seeded_users(self) -> list[User]:
        session = _make_session(user_count=0)
        added: list[list] = []
        session.add_all.side_effect = lambda items: added.append(list(items))
        await seed_database(session)
        return [item for batch in added for item in batch if isinstance(item, User)]

    @pytest.mark.asyncio
    async def test_admin_user_exists(self, seeded_users: list[User]) -> None:
        emails = [u.email for u in seeded_users]
        assert "admin@mxtac.local" in emails

    @pytest.mark.asyncio
    async def test_analyst_user_exists(self, seeded_users: list[User]) -> None:
        emails = [u.email for u in seeded_users]
        assert "analyst@mxtac.local" in emails

    @pytest.mark.asyncio
    async def test_hunter_user_exists(self, seeded_users: list[User]) -> None:
        emails = [u.email for u in seeded_users]
        assert "hunter@mxtac.local" in emails

    @pytest.mark.asyncio
    async def test_engineer_user_exists(self, seeded_users: list[User]) -> None:
        emails = [u.email for u in seeded_users]
        assert "engineer@mxtac.local" in emails

    @pytest.mark.asyncio
    async def test_passwords_are_hashed(self, seeded_users: list[User]) -> None:
        for user in seeded_users:
            assert user.hashed_password != "mxtac2026", (
                f"User {user.email} has unhashed plaintext password"
            )

    @pytest.mark.asyncio
    async def test_all_users_are_active(self, seeded_users: list[User]) -> None:
        for user in seeded_users:
            assert user.is_active is True

    @pytest.mark.asyncio
    async def test_admin_role_is_correct(self, seeded_users: list[User]) -> None:
        admin = next(u for u in seeded_users if u.email == "admin@mxtac.local")
        assert admin.role == "admin"

    @pytest.mark.asyncio
    async def test_unique_emails(self, seeded_users: list[User]) -> None:
        emails = [u.email for u in seeded_users]
        assert len(emails) == len(set(emails))


# ---------------------------------------------------------------------------
# Rule data correctness
# ---------------------------------------------------------------------------


class TestSeedRules:
    """Verifies seeded Sigma rules have required fields."""

    @pytest.fixture
    async def seeded_rules(self) -> list[Rule]:
        session = _make_session(user_count=0)
        added: list[list] = []
        session.add_all.side_effect = lambda items: added.append(list(items))
        await seed_database(session)
        return [item for batch in added for item in batch if isinstance(item, Rule)]

    @pytest.mark.asyncio
    async def test_all_rules_have_title(self, seeded_rules: list[Rule]) -> None:
        for rule in seeded_rules:
            assert rule.title and len(rule.title) > 0

    @pytest.mark.asyncio
    async def test_all_rules_have_yaml_content(self, seeded_rules: list[Rule]) -> None:
        for rule in seeded_rules:
            assert rule.content and "detection:" in rule.content

    @pytest.mark.asyncio
    async def test_all_rules_are_sigma_type(self, seeded_rules: list[Rule]) -> None:
        for rule in seeded_rules:
            assert rule.rule_type == "sigma"

    @pytest.mark.asyncio
    async def test_all_rules_are_enabled(self, seeded_rules: list[Rule]) -> None:
        for rule in seeded_rules:
            assert rule.enabled is True

    @pytest.mark.asyncio
    async def test_all_rules_have_technique_ids(self, seeded_rules: list[Rule]) -> None:
        for rule in seeded_rules:
            assert rule.technique_ids is not None

    @pytest.mark.asyncio
    async def test_dcsync_rule_is_critical(self, seeded_rules: list[Rule]) -> None:
        dcsync = next((r for r in seeded_rules if "DCSync" in r.title), None)
        assert dcsync is not None
        assert dcsync.level == "critical"

    @pytest.mark.asyncio
    async def test_rules_from_sigmahq(self, seeded_rules: list[Rule]) -> None:
        for rule in seeded_rules:
            assert rule.source == "sigmaHQ"


# ---------------------------------------------------------------------------
# Incident data correctness
# ---------------------------------------------------------------------------


class TestSeedIncidents:
    """Verifies seeded incidents are properly formed."""

    @pytest.fixture
    async def seeded_incidents(self) -> list[Incident]:
        session = _make_session(user_count=0)
        added: list[list] = []
        session.add_all.side_effect = lambda items: added.append(list(items))
        await seed_database(session)
        return [item for batch in added for item in batch if isinstance(item, Incident)]

    @pytest.mark.asyncio
    async def test_all_incidents_have_title(self, seeded_incidents: list[Incident]) -> None:
        for inc in seeded_incidents:
            assert inc.title and len(inc.title) > 0

    @pytest.mark.asyncio
    async def test_all_incidents_have_severity(self, seeded_incidents: list[Incident]) -> None:
        valid = {"critical", "high", "medium", "low", "informational"}
        for inc in seeded_incidents:
            assert inc.severity in valid

    @pytest.mark.asyncio
    async def test_all_incidents_have_detection_ids(self, seeded_incidents: list[Incident]) -> None:
        for inc in seeded_incidents:
            assert isinstance(inc.detection_ids, list)
            assert len(inc.detection_ids) > 0

    @pytest.mark.asyncio
    async def test_incident_detection_ids_reference_seeded_detections(
        self, seeded_incidents: list[Incident]
    ) -> None:
        valid_ids = {
            "DET-2026-00847", "DET-2026-00846", "DET-2026-00845", "DET-2026-00844",
            "DET-2026-00843", "DET-2026-00842", "DET-2026-00841", "DET-2026-00840",
            "DET-2026-00839", "DET-2026-00838", "DET-2026-00837",
        }
        for inc in seeded_incidents:
            for det_id in inc.detection_ids:
                assert det_id in valid_ids, f"Unknown detection ID {det_id!r} in incident {inc.title!r}"

    @pytest.mark.asyncio
    async def test_all_incidents_have_hosts(self, seeded_incidents: list[Incident]) -> None:
        for inc in seeded_incidents:
            assert isinstance(inc.hosts, list)
            assert len(inc.hosts) > 0

    @pytest.mark.asyncio
    async def test_critical_incident_has_priority_one(self, seeded_incidents: list[Incident]) -> None:
        critical = next((i for i in seeded_incidents if i.severity == "critical"), None)
        assert critical is not None
        assert critical.priority == 1

    @pytest.mark.asyncio
    async def test_all_incidents_created_by_system(self, seeded_incidents: list[Incident]) -> None:
        for inc in seeded_incidents:
            assert inc.created_by == "system"
