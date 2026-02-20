"""Programmatic Alembic migration runner — feature 20.8 SQLite single-binary mode.

``auto_migrate()`` is called during FastAPI startup when SQLite is in use so
that the database schema is always up-to-date without requiring operators to
run ``alembic upgrade head`` manually.

Implementation notes
--------------------
Alembic's async ``env.py`` calls ``asyncio.run()`` internally.  Calling
``asyncio.run()`` from within the FastAPI event loop would raise
"This event loop is already running."  To avoid the conflict, the migration
is executed in a dedicated ``ThreadPoolExecutor`` worker, which has its own
thread-local state and no running event loop, so Alembic's ``asyncio.run()``
succeeds without interfering with the FastAPI loop.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

logger = logging.getLogger(__name__)

# Absolute path to alembic.ini, resolved relative to this file's location:
#   app/backend/app/db/migrate.py  →  ../../..  →  app/backend/
_ALEMBIC_INI = Path(__file__).parent.parent.parent / "alembic.ini"


def _run_alembic_upgrade() -> None:
    """Run ``alembic upgrade head`` synchronously.

    Safe to call from a thread that has no running event loop.
    ``alembic/env.py`` uses ``asyncio.run()`` internally; since threads
    start with no event loop, this call creates a fresh one and exits
    cleanly.
    """
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(_ALEMBIC_INI))
    # env.py reads settings.database_url directly, so no override is needed.
    command.upgrade(cfg, "head")


async def auto_migrate() -> None:
    """Apply all pending Alembic migrations asynchronously.

    Runs the Alembic upgrade in a dedicated background thread so that
    Alembic's internal ``asyncio.run()`` call (in env.py) can create its
    own event loop without conflicting with the FastAPI event loop.

    Logs at INFO on success and at ERROR on failure; exceptions are
    swallowed so a migration failure does not abort startup entirely.
    """
    logger.info("SQLite mode: running auto-migration (alembic upgrade head)")
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="alembic") as pool:
        try:
            await loop.run_in_executor(pool, _run_alembic_upgrade)
            logger.info("Auto-migration complete")
        except Exception:
            logger.exception(
                "Auto-migration failed — database schema may be incomplete. "
                "Run 'alembic upgrade head' manually to apply pending migrations."
            )
