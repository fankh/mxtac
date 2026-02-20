"""Tests for app/core/logging.py — Feature 21.10: Structured JSON logging in production

``configure_logging()`` wires up the root logger with either a human-readable
format (debug mode) or structured JSON format (production mode), and quiets
noisy third-party loggers.  ``get_logger()`` is a thin wrapper around the
standard ``logging.getLogger()``.

Coverage:
  LOG_FORMAT_JSON — contains all required JSON field placeholders
  LOG_FORMAT_DEV  — contains human-readable format placeholders
  configure_logging (debug=True)  — root level DEBUG, DEV format, stdout stream
  configure_logging (debug=True)  — uvicorn.access → WARNING, sqlalchemy.engine → INFO
  configure_logging (debug=False) — root level INFO, JSON format, stdout stream
  configure_logging (debug=False) — uvicorn.access → WARNING, sqlalchemy.engine → WARNING
  configure_logging               — replaces pre-existing handlers (not appends)
  configure_logging               — calling twice leaves exactly one handler
  configure_logging               — formatter uses ISO 8601 datefmt (%Y-%m-%dT%H:%M:%S)
  configure_logging               — emitted log record format (dev and JSON)
  get_logger — returns logging.Logger instance
  get_logger — logger carries the given name
  get_logger — same name returns the same logger object (registry identity)
  get_logger — distinct names return distinct logger objects
"""

from __future__ import annotations

import logging
import sys
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from app.core.logging import LOG_FORMAT_DEV, LOG_FORMAT_JSON, configure_logging, get_logger

# ---------------------------------------------------------------------------
# Patch target — the ``settings`` object as imported by the logging module
# ---------------------------------------------------------------------------

_SETTINGS_PATH = "app.core.logging.settings"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_root_logger():
    """Capture and fully restore root-logger state around every test.

    configure_logging() replaces root.handlers and adjusts levels on several
    named loggers; without this fixture tests would bleed state into each other.
    """
    root = logging.getLogger()
    saved_level = root.level
    saved_handlers = root.handlers[:]

    uvicorn_logger = logging.getLogger("uvicorn.access")
    sqlalchemy_logger = logging.getLogger("sqlalchemy.engine")
    saved_uvicorn_level = uvicorn_logger.level
    saved_sqlalchemy_level = sqlalchemy_logger.level

    yield

    root.setLevel(saved_level)
    root.handlers = saved_handlers
    uvicorn_logger.setLevel(saved_uvicorn_level)
    sqlalchemy_logger.setLevel(saved_sqlalchemy_level)


def _mock_settings(*, debug: bool) -> MagicMock:
    """Build a minimal settings mock with just the ``debug`` attribute."""
    m = MagicMock()
    m.debug = debug
    return m


# ---------------------------------------------------------------------------
# TestLogFormatConstants
# ---------------------------------------------------------------------------


class TestLogFormatConstants:
    """The two format-string constants are well-formed and contain required fields."""

    def test_json_format_contains_asctime(self) -> None:
        assert "%(asctime)s" in LOG_FORMAT_JSON

    def test_json_format_contains_levelname(self) -> None:
        assert "%(levelname)s" in LOG_FORMAT_JSON

    def test_json_format_contains_name(self) -> None:
        assert "%(name)s" in LOG_FORMAT_JSON

    def test_json_format_contains_message(self) -> None:
        assert "%(message)s" in LOG_FORMAT_JSON

    def test_json_format_starts_with_brace(self) -> None:
        """Template looks like a JSON object literal."""
        assert LOG_FORMAT_JSON.lstrip().startswith("{")

    def test_json_format_ends_with_brace(self) -> None:
        assert LOG_FORMAT_JSON.rstrip().endswith("}")

    def test_dev_format_contains_asctime(self) -> None:
        assert "%(asctime)s" in LOG_FORMAT_DEV

    def test_dev_format_contains_levelname(self) -> None:
        assert "%(levelname)s" in LOG_FORMAT_DEV

    def test_dev_format_contains_name(self) -> None:
        assert "%(name)s" in LOG_FORMAT_DEV

    def test_dev_format_contains_message(self) -> None:
        assert "%(message)s" in LOG_FORMAT_DEV

    def test_dev_format_is_distinct_from_json_format(self) -> None:
        assert LOG_FORMAT_DEV != LOG_FORMAT_JSON


# ---------------------------------------------------------------------------
# TestConfigureLoggingDebugMode
# ---------------------------------------------------------------------------


class TestConfigureLoggingDebugMode:
    """configure_logging() with settings.debug=True — development / DEBUG behaviour."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        with patch(_SETTINGS_PATH, _mock_settings(debug=True)):
            configure_logging()

    def test_root_logger_level_is_debug(self) -> None:
        assert logging.getLogger().level == logging.DEBUG

    def test_root_logger_has_exactly_one_handler(self) -> None:
        assert len(logging.getLogger().handlers) == 1

    def test_handler_is_stream_handler(self) -> None:
        handler = logging.getLogger().handlers[0]
        assert isinstance(handler, logging.StreamHandler)

    def test_handler_streams_to_stdout(self) -> None:
        handler = logging.getLogger().handlers[0]
        assert handler.stream is sys.stdout

    def test_formatter_uses_dev_format(self) -> None:
        fmt = logging.getLogger().handlers[0].formatter
        assert fmt is not None
        assert fmt._fmt == LOG_FORMAT_DEV

    def test_formatter_uses_iso8601_datefmt(self) -> None:
        fmt = logging.getLogger().handlers[0].formatter
        assert fmt is not None
        assert fmt.datefmt == "%Y-%m-%dT%H:%M:%S"

    def test_uvicorn_access_level_is_warning(self) -> None:
        assert logging.getLogger("uvicorn.access").level == logging.WARNING

    def test_sqlalchemy_engine_level_is_info_in_debug_mode(self) -> None:
        assert logging.getLogger("sqlalchemy.engine").level == logging.INFO


# ---------------------------------------------------------------------------
# TestConfigureLoggingProductionMode
# ---------------------------------------------------------------------------


class TestConfigureLoggingProductionMode:
    """configure_logging() with settings.debug=False — production / JSON behaviour."""

    @pytest.fixture(autouse=True)
    def _setup(self) -> None:
        with patch(_SETTINGS_PATH, _mock_settings(debug=False)):
            configure_logging()

    def test_root_logger_level_is_info(self) -> None:
        assert logging.getLogger().level == logging.INFO

    def test_root_logger_has_exactly_one_handler(self) -> None:
        assert len(logging.getLogger().handlers) == 1

    def test_handler_is_stream_handler(self) -> None:
        handler = logging.getLogger().handlers[0]
        assert isinstance(handler, logging.StreamHandler)

    def test_handler_streams_to_stdout(self) -> None:
        handler = logging.getLogger().handlers[0]
        assert handler.stream is sys.stdout

    def test_formatter_uses_json_format(self) -> None:
        fmt = logging.getLogger().handlers[0].formatter
        assert fmt is not None
        assert fmt._fmt == LOG_FORMAT_JSON

    def test_formatter_uses_iso8601_datefmt(self) -> None:
        fmt = logging.getLogger().handlers[0].formatter
        assert fmt is not None
        assert fmt.datefmt == "%Y-%m-%dT%H:%M:%S"

    def test_uvicorn_access_level_is_warning(self) -> None:
        assert logging.getLogger("uvicorn.access").level == logging.WARNING

    def test_sqlalchemy_engine_level_is_warning_in_production(self) -> None:
        assert logging.getLogger("sqlalchemy.engine").level == logging.WARNING


# ---------------------------------------------------------------------------
# TestConfigureLoggingHandlerManagement
# ---------------------------------------------------------------------------


class TestConfigureLoggingHandlerManagement:
    """configure_logging() always replaces handlers — never appends."""

    def test_replaces_pre_existing_handlers(self) -> None:
        root = logging.getLogger()
        # Seed the root logger with two dummy handlers
        root.handlers = [logging.NullHandler(), logging.NullHandler()]

        with patch(_SETTINGS_PATH, _mock_settings(debug=True)):
            configure_logging()

        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0], logging.StreamHandler)

    def test_calling_twice_leaves_one_handler(self) -> None:
        with patch(_SETTINGS_PATH, _mock_settings(debug=True)):
            configure_logging()
            configure_logging()

        assert len(logging.getLogger().handlers) == 1

    def test_calling_twice_updates_format_to_latest_settings(self) -> None:
        """Second call with different settings takes effect."""
        with patch(_SETTINGS_PATH, _mock_settings(debug=True)):
            configure_logging()

        with patch(_SETTINGS_PATH, _mock_settings(debug=False)):
            configure_logging()

        fmt = logging.getLogger().handlers[0].formatter
        assert fmt is not None
        assert fmt._fmt == LOG_FORMAT_JSON


# ---------------------------------------------------------------------------
# TestConfigureLoggingEmittedOutput
# ---------------------------------------------------------------------------


class TestConfigureLoggingEmittedOutput:
    """Verify the actual text produced when a record is emitted."""

    def _capture_output(self, *, debug: bool, message: str) -> str:
        """Configure logging into a StringIO buffer and return the emitted line."""
        buf = StringIO()
        with patch(_SETTINGS_PATH, _mock_settings(debug=debug)):
            configure_logging()

        # Swap the handler's stream to our buffer so we can capture output
        handler = logging.getLogger().handlers[0]
        handler.stream = buf

        test_logger = logging.getLogger("test.output")
        test_logger.info(message)

        return buf.getvalue()

    def test_json_output_contains_level_field(self) -> None:
        output = self._capture_output(debug=False, message='"hello"')
        assert '"level"' in output

    def test_json_output_contains_logger_field(self) -> None:
        output = self._capture_output(debug=False, message='"hello"')
        assert '"logger"' in output

    def test_json_output_contains_time_field(self) -> None:
        output = self._capture_output(debug=False, message='"hello"')
        assert '"time"' in output

    def test_json_output_starts_with_brace(self) -> None:
        output = self._capture_output(debug=False, message='"hello"')
        assert output.lstrip().startswith("{")

    def test_dev_output_contains_logger_name(self) -> None:
        output = self._capture_output(debug=True, message="hello dev")
        assert "test.output" in output

    def test_dev_output_contains_level_name(self) -> None:
        output = self._capture_output(debug=True, message="hello dev")
        assert "INFO" in output

    def test_dev_output_contains_message_text(self) -> None:
        output = self._capture_output(debug=True, message="hello dev")
        assert "hello dev" in output


# ---------------------------------------------------------------------------
# TestGetLogger
# ---------------------------------------------------------------------------


class TestGetLogger:
    """get_logger() is a transparent wrapper around logging.getLogger()."""

    def test_returns_logger_instance(self) -> None:
        logger = get_logger("mxtac.test")
        assert isinstance(logger, logging.Logger)

    def test_logger_carries_given_name(self) -> None:
        logger = get_logger("mxtac.service.auth")
        assert logger.name == "mxtac.service.auth"

    def test_same_name_returns_same_object(self) -> None:
        """Python's logging registry must be used — no new instances."""
        a = get_logger("mxtac.singleton")
        b = get_logger("mxtac.singleton")
        assert a is b

    def test_distinct_names_return_distinct_loggers(self) -> None:
        a = get_logger("mxtac.alpha")
        b = get_logger("mxtac.beta")
        assert a is not b
        assert a.name != b.name

    def test_logger_name_matches_standard_getlogger(self) -> None:
        """get_logger() must delegate to the standard logging registry."""
        logger = get_logger("mxtac.delegated")
        assert logger is logging.getLogger("mxtac.delegated")

    def test_accepts_dotted_hierarchical_name(self) -> None:
        logger = get_logger("app.core.services.detection")
        assert logger.name == "app.core.services.detection"
