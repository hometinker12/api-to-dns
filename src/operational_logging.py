"""Python logger setup for stdout and optional rotating files.

This is intentionally separate from the database-backed activity/audit log.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler

from .log_constants import (
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFORMATIONAL,
    LOG_LEVEL_VALUES,
    LOG_LEVEL_VERBOSE,
    LOG_LEVEL_WARNING,
)

LOGGER = logging.getLogger("api_to_dns")

SETTING_LOG_FILE = "operational_log_file"
SETTING_LOG_MAX_BYTES = "operational_log_max_bytes"
SETTING_LOG_BACKUP_COUNT = "operational_log_backup_count"


def _normalize_level(level: str) -> str:
    cleaned = (level or "").strip().upper()
    if cleaned not in LOG_LEVEL_VALUES:
        return LOG_LEVEL_INFORMATIONAL
    return cleaned


def configure_operational_logging(
    *,
    level: str = LOG_LEVEL_INFORMATIONAL,
    log_file: str | None = None,
    max_bytes: int = 1_048_576,
    backup_count: int = 5,
) -> None:
    """Configure the Python ``api_to_dns`` logger.

    This is intentionally separate from the database-backed audit log; it
    powers stdout/stderr for container deployments and an optional rotating
    file handler for non-Docker installs.
    """
    py_level = {
        LOG_LEVEL_VERBOSE: logging.DEBUG,
        LOG_LEVEL_INFORMATIONAL: logging.INFO,
        LOG_LEVEL_WARNING: logging.WARNING,
        LOG_LEVEL_ERROR: logging.ERROR,
    }.get(_normalize_level(level), logging.INFO)

    LOGGER.setLevel(py_level)
    for handler in list(LOGGER.handlers):
        LOGGER.removeHandler(handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    LOGGER.addHandler(stream_handler)

    target_file = log_file or os.getenv("LOG_FILE")
    if target_file:
        try:
            os.makedirs(os.path.dirname(target_file) or ".", exist_ok=True)
            file_handler = RotatingFileHandler(
                target_file, maxBytes=max(1024, int(max_bytes)), backupCount=max(0, int(backup_count))
            )
            file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            LOGGER.addHandler(file_handler)
        except OSError:  # pragma: no cover - best-effort file logging only
            LOGGER.exception("could not configure rotating file handler for %s", target_file)
