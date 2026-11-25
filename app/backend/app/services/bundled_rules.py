"""Import the Sigma rules shipped in ``sigma_rules/`` into the ``rules`` table.

The ``rules`` table is the single source of truth for the Sigma engine, the
Sigma Rules page and ATT&CK coverage.  At startup every bundled rule file whose
Sigma ``id`` is not yet in the table is inserted with ``source="bundled"``.

The import never updates an existing row: a rule the user has edited or
disabled keeps its content and state, and running the import again is a no-op.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.logging import get_logger
from ..engine.sigma_engine import SigmaEngine, SigmaRuleError
from ..models.rule import Rule
from ..repositories.rule_repo import RuleRepo

logger = get_logger(__name__)

BUNDLED_RULES_DIR = Path(__file__).parent.parent.parent / "sigma_rules"
BUNDLED_SOURCE = "bundled"


def _read_bundled_rules(directory: Path) -> dict[str, dict[str, Any]]:
    """Parse every rule file in *directory* into ``{rule_id: Rule column values}``.

    Files that are invalid, unsupported by the engine or have no ``id`` are
    skipped with a warning — without a stable id the import could not be
    idempotent.
    """
    engine = SigmaEngine()
    rules: dict[str, dict[str, Any]] = {}
    for path in sorted(directory.rglob("*.y*ml")):
        content = path.read_text(encoding="utf-8")
        try:
            sigma_rule = engine.parse_rule_yaml(content)
            if "id" not in yaml.safe_load(content):
                raise SigmaRuleError("bundled rule has no 'id'")
        except SigmaRuleError as exc:
            logger.warning("Skipping bundled rule file=%s: %s", path.name, exc)
            continue
        logsource = sigma_rule.logsource
        rules[sigma_rule.id] = {
            "id": sigma_rule.id,
            "title": sigma_rule.title,
            "description": sigma_rule.description or "",
            "content": content,
            "status": sigma_rule.status,
            "level": sigma_rule.level,
            "enabled": True,
            "logsource_product": logsource.get("product"),
            "logsource_category": logsource.get("category"),
            "logsource_service": logsource.get("service"),
            "technique_ids": json.dumps(sigma_rule.technique_ids),
            "tactic_ids": json.dumps(sigma_rule.tactic_ids),
            "source": BUNDLED_SOURCE,
        }
    return rules


async def import_bundled_rules(
    session: AsyncSession, directory: Path = BUNDLED_RULES_DIR
) -> int:
    """Insert bundled rules that are not in the ``rules`` table yet.

    Returns the number of rules inserted.
    """
    if not directory.exists():
        logger.info("No bundled rule directory at %s", directory)
        return 0

    bundled = _read_bundled_rules(directory)
    if not bundled:
        return 0
    result = await session.execute(select(Rule.id).where(Rule.id.in_(bundled)))
    existing = set(result.scalars().all())
    missing = [columns for rule_id, columns in bundled.items() if rule_id not in existing]

    try:
        for columns in missing:
            await RuleRepo.create(session, **columns)
        await session.commit()
    except IntegrityError:
        # Another backend replica imported the same rules at the same moment.
        await session.rollback()
        logger.info("Bundled rules were imported concurrently by another instance")
        return 0

    logger.info("Imported %d bundled Sigma rules (%d already present)", len(missing), len(existing))
    return len(missing)
