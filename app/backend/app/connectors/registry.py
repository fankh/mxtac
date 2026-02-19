"""Connector registry — maps connector types to classes and starts connectors from DB."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.logging import get_logger
from ..models.connector import Connector
from ..pipeline.queue import MessageQueue
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
