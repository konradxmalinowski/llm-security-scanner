from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

_LOGGER_NAME = "llm_scanner"

# Standard attributes present on every logging.LogRecord — anything else found on
# a record's __dict__ came from an `extra=` mapping and should be merged into the
# JSON payload (e.g. scan_id, event, attack_id, target_latency_s).
_RESERVED_RECORD_ATTRS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "message",
        "taskName",
    }
)


class JsonFormatter(logging.Formatter):
    """Formats each log record as a single JSON line.

    Always includes timestamp, level, logger, message; merges in any fields
    passed via `extra=` on the log call (e.g. scan_id, event, attack_id).
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED_RECORD_ATTRS:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str, log_file: Path | None) -> None:
    """Configure the "llm_scanner" namespaced logger.

    Attaches a human-readable StreamHandler to stderr (never stdout — stdout is
    reserved for Rich console output), and, only if `log_file` is given, an
    additional FileHandler writing JSON lines via JsonFormatter. Safe to call
    more than once (e.g. across tests): existing handlers are replaced rather
    than accumulated.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(level.upper())
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    stream_handler = logging.StreamHandler(stream=sys.stderr)
    stream_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    )
    logger.addHandler(stream_handler)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)


def get_logger() -> logging.Logger:
    """Return the "llm_scanner" namespaced logger."""
    return logging.getLogger(_LOGGER_NAME)
