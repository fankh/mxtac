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
from .prowler import ProwlerConnector
from .opencti import OpenCTIConnector

logger = get_logger(__name__)

CONNECTOR_TYPES: dict[str, type[BaseConnector]] = {
    "wazuh": WazuhConnector,
    "zeek": ZeekConnector,
    "suricata": SuricataConnector,
    "prowler": ProwlerConnector,
    "opencti": OpenCTIConnector,
}

# ── Feature 6.10 / 6.17: connector offset state file helpers ──────────────────

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


# ── Feature 6.17: Suricata offset state file helpers ──────────────────────────


def _suricata_state_file(connector_name: str) -> Path:
    """Return the path of the JSON state file for a Suricata connector."""
    return _STATE_DIR / f"suricata_offset_{connector_name}.json"


def _load_suricata_position(state_file: Path) -> int | None:
    """Load persisted byte offset from *state_file*. Returns None on any error."""
    try:
        if state_file.exists():
            data = json.loads(state_file.read_text())
            if isinstance(data, int):
                return data
    except Exception as exc:
        logger.warning("Failed to load Suricata state file=%s err=%s", state_file, exc)
    return None


def _save_suricata_position(state_file: Path, position: int) -> None:
    """Atomically write *position* to *state_file* (write-then-rename)."""
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(position))
        tmp.rename(state_file)
    except Exception as exc:
        logger.warning("Failed to save Suricata state file=%s err=%s", state_file, exc)


# ── Feature 6.19: Prowler timestamp state file helpers ────────────────────────


def _prowler_state_file(connector_name: str) -> Path:
    """Return the path of the JSON state file for a Prowler connector."""
    return _STATE_DIR / f"prowler_timestamp_{connector_name}.json"


def _load_prowler_timestamp(state_file: Path) -> datetime | None:
    """Load persisted ISO timestamp from *state_file*. Returns None on any error."""
    try:
        if state_file.exists():
            data = json.loads(state_file.read_text())
            if isinstance(data, str):
                return datetime.fromisoformat(data)
    except Exception as exc:
        logger.warning("Failed to load Prowler state file=%s err=%s", state_file, exc)
    return None


def _save_prowler_timestamp(state_file: Path, ts: datetime) -> None:
    """Atomically write *ts* ISO string to *state_file* (write-then-rename)."""
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(ts.isoformat()))
        tmp.rename(state_file)
    except Exception as exc:
        logger.warning("Failed to save Prowler state file=%s err=%s", state_file, exc)


# ── Feature 6.20: OpenCTI timestamp state file helpers ────────────────────────


def _opencti_state_file(connector_name: str) -> Path:
    """Return the path of the JSON state file for an OpenCTI connector."""
    return _STATE_DIR / f"opencti_timestamp_{connector_name}.json"


def _load_opencti_timestamp(state_file: Path) -> datetime | None:
    """Load persisted ISO timestamp from *state_file*. Returns None on any error."""
    try:
        if state_file.exists():
            data = json.loads(state_file.read_text())
            if isinstance(data, str):
                return datetime.fromisoformat(data)
    except Exception as exc:
        logger.warning("Failed to load OpenCTI state file=%s err=%s", state_file, exc)
    return None


def _save_opencti_timestamp(state_file: Path, ts: datetime) -> None:
    """Atomically write *ts* ISO string to *state_file* (write-then-rename)."""
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(ts.isoformat()))
        tmp.rename(state_file)
    except Exception as exc:
        logger.warning("Failed to save OpenCTI state file=%s err=%s", state_file, exc)


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

    # Feature 6.6: shared status_callback — persists status + error_message to DB
    connector_id = db_conn.id

    async def _status_cb(
        status: str,
        error_message: str | None,
        _id: str = connector_id,
    ) -> None:
        from ..core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            await ConnectorRepo.update_status(session, _id, status, error_message)
            await session.commit()

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
            status_callback=_status_cb,
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
            status_callback=_status_cb,
        )

    if cls is SuricataConnector:
        # Feature 6.17: persist byte offset so restarts resume where they left off
        state_file = _suricata_state_file(db_conn.name)
        initial_position = _load_suricata_position(state_file)

        async def _suricata_checkpoint(
            position: int,
            _sf: Path = state_file,
        ) -> None:
            _save_suricata_position(_sf, position)

        return SuricataConnector(
            config,
            queue,
            initial_position=initial_position,
            checkpoint_callback=_suricata_checkpoint,
            status_callback=_status_cb,
        )

    if cls is ProwlerConnector:
        # Feature 6.19: persist fetch timestamp so restarts do not re-ingest findings
        state_file = _prowler_state_file(db_conn.name)
        initial_ts = _load_prowler_timestamp(state_file)

        async def _prowler_checkpoint(
            ts: datetime,
            _sf: Path = state_file,
        ) -> None:
            _save_prowler_timestamp(_sf, ts)

        return ProwlerConnector(
            config,
            queue,
            initial_last_fetched_at=initial_ts,
            checkpoint_callback=_prowler_checkpoint,
            status_callback=_status_cb,
        )

    if cls is OpenCTIConnector:
        # Feature 6.20: persist fetch timestamp so restarts do not re-ingest objects
        state_file = _opencti_state_file(db_conn.name)
        initial_ts = _load_opencti_timestamp(state_file)

        async def _opencti_checkpoint(
            ts: datetime,
            _sf: Path = state_file,
        ) -> None:
            _save_opencti_timestamp(_sf, ts)

        return OpenCTIConnector(
            config,
            queue,
            initial_last_fetched_at=initial_ts,
            checkpoint_callback=_opencti_checkpoint,
            status_callback=_status_cb,
        )

    return cls(config, queue, status_callback=_status_cb)


async def start_connectors_from_db(
    session: AsyncSession,
    queue: MessageQueue,
) -> dict[str, BaseConnector]:
    """Load enabled connectors from DB and return {connector_id: connector} mapping.

    Feature 6.24: Each connector is loaded independently — an error building one
    connector is logged and skipped so that remaining connectors still start.
    """
    result = await session.execute(
        select(Connector).where(Connector.enabled == True)
    )
    db_connectors = result.scalars().all()

    connectors: dict[str, BaseConnector] = {}
    skipped = 0
    for db_conn in db_connectors:
        try:
            conn = build_connector(db_conn, queue)
            if conn:
                connectors[db_conn.id] = conn
                logger.info(
                    "Registered connector name=%s type=%s",
                    db_conn.name,
                    db_conn.connector_type,
                )
            else:
                skipped += 1
        except Exception:
            skipped += 1
            logger.exception(
                "Failed to load connector name=%s type=%s — skipping",
                db_conn.name,
                db_conn.connector_type,
            )

    if skipped:
        logger.warning("Skipped %d connector(s) due to errors or unknown type", skipped)

    return connectors
