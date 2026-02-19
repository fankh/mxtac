"""Structured logging configuration for MxTac backend."""

import logging
import sys

from .config import settings

LOG_FORMAT_JSON = (
    '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)s}'
)
LOG_FORMAT_DEV = "%(asctime)s | %(levelname)-8s | %(name)s — %(message)s"


def configure_logging() -> None:
    level = logging.DEBUG if settings.debug else logging.INFO
    fmt = LOG_FORMAT_DEV if settings.debug else LOG_FORMAT_JSON

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S"))

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = [handler]

    # Quiet down noisy libs
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(
        logging.INFO if settings.debug else logging.WARNING
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
