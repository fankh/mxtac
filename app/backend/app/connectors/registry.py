"""Connector registry — maps connector types to classes and starts connectors from DB."""

from __future__ import annotations

import json
from datetime import datetime
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

    return cls(config, queue)


async def start_connectors_from_db(
    session: AsyncSession,
    queue: MessageQueue,
) -> list[BaseConnector]:
    """Load enabled connectors from DB and return instantiated connector objects."""
    result = await session.execute(
        select(Connector).where(Connector.enabled == True)
    )
    db_connectors = result.scalars().all()

    connectors: list[BaseConnector] = []
    for db_conn in db_connectors:
        conn = build_connector(db_conn, queue)
        if conn:
            connectors.append(conn)
            logger.info("Registered connector name=%s type=%s", db_conn.name, db_conn.connector_type)

    return connectors
