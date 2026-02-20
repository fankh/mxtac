"""Connector registry — maps connector types to classes and starts connectors from DB."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.logging import get_logger
from ..models.connector import Connector
from ..pipeline.queue import MessageQueue
from ..repositories.connector_repo import ConnectorRepo
from .base import BaseConnector, ConnectorConfig
from .wazuh import WazuhConnector
from .zeek import ZeekConnector
from .suricata import SuricataConnector

logger = get_logger(__name__)

CONNECTOR_TYPES: dict[str, type[BaseConnector]] = {
    "wazuh": WazuhConnector,
    "zeek": ZeekConnector,
    "suricata": SuricataConnector,
}

# ── Feature 6.10: Zeek offset state file helpers ──────────────────────────────

_STATE_DIR = Path(os.environ.get("MXTAC_STATE_DIR", "/var/lib/mxtac"))


def _zeek_state_file(connector_name: str) -> Path:
    """Return the path of the JSON state file for a Zeek connector."""
    return _STATE_DIR / f"zeek_offsets_{connector_name}.json"


def _load_zeek_positions(state_file: Path) -> dict[str, int] | None:
    """Load persisted byte offsets from *state_file*. Returns None on any error."""
    try:
        if state_file.exists():
            data = json.loads(state_file.read_text())
            if isinstance(data, dict):
                return {k: int(v) for k, v in data.items()}
    except Exception as exc:
        logger.warning("Failed to load Zeek state file=%s err=%s", state_file, exc)
    return None


def _save_zeek_positions(state_file: Path, positions: dict[str, int]) -> None:
    """Atomically write *positions* to *state_file* (write-then-rename)."""
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(positions))
        tmp.rename(state_file)
    except Exception as exc:
        logger.warning("Failed to save Zeek state file=%s err=%s", state_file, exc)


def build_connector(db_conn: Connector, queue: MessageQueue) -> BaseConnector | None:
    """Create a connector instance from a DB connector row."""
    cls = CONNECTOR_TYPES.get(db_conn.connector_type)
    if not cls:
        logger.warning("Unknown connector type=%s name=%s", db_conn.connector_type, db_conn.name)
        return None

    extra = json.loads(db_conn.config_json) if db_conn.config_json else {}
    config = ConnectorConfig(
        name=db_conn.name,
        connector_type=db_conn.connector_type,
        enabled=db_conn.enabled,
        poll_interval_seconds=extra.pop("poll_interval_seconds", 60),
        extra=extra,
    )

    if cls is WazuhConnector:
        # Feature 6.3: load persisted timestamp to avoid re-ingesting on restart
        initial_last_fetched_at: datetime | None = None
        if db_conn.last_seen_at:
            try:
                initial_last_fetched_at = datetime.fromisoformat(db_conn.last_seen_at)
            except ValueError:
                logger.warning(
                    "Ignoring invalid last_seen_at for connector=%s value=%r",
                    db_conn.name,
                    db_conn.last_seen_at,
                )

        connector_id = db_conn.id

        async def _checkpoint(ts: datetime, _id: str = connector_id) -> None:
            from ..core.database import AsyncSessionLocal
            async with AsyncSessionLocal() as session:
                await ConnectorRepo.update(session, _id, last_seen_at=ts.isoformat())
                await session.commit()

        return WazuhConnector(
            config,
            queue,
            initial_last_fetched_at=initial_last_fetched_at,
            checkpoint_callback=_checkpoint,
        )

    if cls is ZeekConnector:
        # Feature 6.10: persist byte offsets so restarts resume where they left off
        state_file = _zeek_state_file(db_conn.name)
        initial_positions = _load_zeek_positions(state_file)

        async def _zeek_checkpoint(
            positions: dict[str, int],
            _sf: Path = state_file,
        ) -> None:
            _save_zeek_positions(_sf, positions)

        return ZeekConnector(
            config,
            queue,
            initial_positions=initial_positions,
            checkpoint_callback=_zeek_checkpoint,
        )

    return cls(config, queue)


async def start_connectors_from_db(
    session: AsyncSession,
    queue: MessageQueue,
) -> dict[str, BaseConnector]:
    """Load enabled connectors from DB and return {connector_id: connector} mapping."""
    result = await session.execute(
        select(Connector).where(Connector.enabled == True)
    )
    db_connectors = result.scalars().all()

    connectors: dict[str, BaseConnector] = {}
    for db_conn in db_connectors:
        conn = build_connector(db_conn, queue)
        if conn:
            connectors[db_conn.id] = conn
            logger.info("Registered connector name=%s type=%s", db_conn.name, db_conn.connector_type)

    return connectors
