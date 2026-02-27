"""Tests for Alembic migration chain integrity (feature 34.4 — CI migration check)

Validates the migration chain without a live database:
  - All migration files in alembic/versions/ are loadable
  - Each migration declares revision, down_revision, upgrade, and downgrade
  - The chain is strictly linear (no branches — exactly one head)
  - Every down_revision references an existing revision (no dangling pointers)
  - The first migration has down_revision = None
  - Each revision ID is unique (no duplicates)
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Optional

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VERSIONS_DIR = Path(__file__).parents[2] / "alembic" / "versions"


def _load_migration(path: Path) -> ModuleType:
    """Load a migration module directly from disk."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _load_all_migrations() -> list[ModuleType]:
    """Return all migration modules sorted by filename."""
    paths = sorted(_VERSIONS_DIR.glob("*.py"))
    return [_load_migration(p) for p in paths if p.stem != "__init__"]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def all_migrations() -> list[ModuleType]:
    return _load_all_migrations()


@pytest.fixture(scope="module")
def revision_map(all_migrations: list[ModuleType]) -> dict[str, ModuleType]:
    """Build a revision_id → module mapping."""
    return {m.revision: m for m in all_migrations}


@pytest.fixture(scope="module")
def heads(revision_map: dict[str, ModuleType]) -> list[str]:
    """Return all revision IDs that are not referenced as any down_revision."""
    all_revisions = set(revision_map.keys())
    referenced_as_parent = {
        m.down_revision
        for m in revision_map.values()
        if m.down_revision is not None
    }
    return sorted(all_revisions - referenced_as_parent)


# ---------------------------------------------------------------------------
# Chain integrity tests
# ---------------------------------------------------------------------------


class TestMigrationChain:
    """The migration revision chain is linear, complete, and self-consistent."""

    def test_at_least_one_migration_exists(self, all_migrations: list[ModuleType]) -> None:
        assert len(all_migrations) > 0

    def test_each_migration_has_revision_attribute(self, all_migrations: list[ModuleType]) -> None:
        for m in all_migrations:
            assert hasattr(m, "revision"), f"{m.__name__} missing 'revision'"
            assert isinstance(m.revision, str), f"{m.__name__}.revision must be str"
            assert m.revision, f"{m.__name__}.revision must not be empty"

    def test_each_migration_has_down_revision_attribute(self, all_migrations: list[ModuleType]) -> None:
        for m in all_migrations:
            assert hasattr(m, "down_revision"), f"{m.__name__} missing 'down_revision'"

    def test_each_migration_has_upgrade_callable(self, all_migrations: list[ModuleType]) -> None:
        for m in all_migrations:
            assert callable(getattr(m, "upgrade", None)), (
                f"{m.__name__} missing callable 'upgrade'"
            )

    def test_each_migration_has_downgrade_callable(self, all_migrations: list[ModuleType]) -> None:
        for m in all_migrations:
            assert callable(getattr(m, "downgrade", None)), (
                f"{m.__name__} missing callable 'downgrade'"
            )

    def test_revision_ids_are_unique(self, all_migrations: list[ModuleType]) -> None:
        ids = [m.revision for m in all_migrations]
        assert len(ids) == len(set(ids)), (
            f"Duplicate revision IDs: {[x for x in ids if ids.count(x) > 1]}"
        )

    def test_exactly_one_head(self, heads: list[str]) -> None:
        """A linear chain has exactly one terminal revision (the head).

        Multiple heads indicate a branched chain, which breaks upgrade/downgrade.
        """
        assert len(heads) == 1, (
            f"Expected exactly 1 migration head, found {len(heads)}: {heads}. "
            "The migration chain is branched — merge or reorder revisions."
        )

    def test_exactly_one_root(self, all_migrations: list[ModuleType]) -> None:
        """Exactly one migration must have down_revision = None (the initial migration)."""
        roots = [m for m in all_migrations if m.down_revision is None]
        assert len(roots) == 1, (
            f"Expected exactly 1 root migration (down_revision=None), found {len(roots)}: "
            f"{[m.revision for m in roots]}"
        )

    def test_root_migration_is_0001(self, all_migrations: list[ModuleType]) -> None:
        roots = [m for m in all_migrations if m.down_revision is None]
        assert roots[0].revision == "0001"

    def test_all_down_revisions_reference_existing_revisions(
        self, all_migrations: list[ModuleType], revision_map: dict[str, ModuleType]
    ) -> None:
        """No down_revision points to a non-existent revision (dangling pointer)."""
        for m in all_migrations:
            if m.down_revision is not None:
                assert m.down_revision in revision_map, (
                    f"Revision {m.revision!r} has down_revision={m.down_revision!r} "
                    f"which does not exist in the migration chain."
                )

    def test_chain_is_fully_reachable_from_head(
        self, heads: list[str], revision_map: dict[str, ModuleType]
    ) -> None:
        """Walk the chain from head to root — every migration must be reachable."""
        if len(heads) != 1:
            pytest.skip("Chain is branched; skipping reachability check")

        visited: list[str] = []
        current: Optional[str] = heads[0]
        while current is not None:
            assert current in revision_map, (
                f"Revision {current!r} referenced in chain but not found in versions/"
            )
            visited.append(current)
            current = revision_map[current].down_revision

        total = len(revision_map)
        assert len(visited) == total, (
            f"Chain walk reached {len(visited)} revisions but {total} exist. "
            f"Unreachable: {set(revision_map) - set(visited)}"
        )

    def test_no_branch_labels(self, all_migrations: list[ModuleType]) -> None:
        """No migration should declare a branch_labels — branches are not permitted."""
        for m in all_migrations:
            branch_labels = getattr(m, "branch_labels", None)
            assert branch_labels is None, (
                f"Revision {m.revision!r} declares branch_labels={branch_labels!r}. "
                "Branch labels create parallel chains and break linear history."
            )
