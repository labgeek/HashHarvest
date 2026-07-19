"""Logging configuration for HashHarvest.

``setup_logging`` wires the ``hashharvest`` logger to a rotating file (under
``~/.hashharvest/logs/``) and the console; call it once at startup. ``capture_logs``
buffers everything the logger emits during a block so a single scan's log can be
stored alongside its scan record.

Log level comes from the ``HASHHARVEST_LOG_LEVEL`` environment variable (default
INFO) until the Phase 3 CLI adds a ``--log-level`` flag.
"""

import io
import logging
import os
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOGGER_NAME = "hashharvest"
_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_configured = False


def setup_logging(level=None):
    """Configure the ``hashharvest`` logger (idempotent). Returns the logger."""
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    if level is None:
        level = os.environ.get("HASHHARVEST_LOG_LEVEL", "INFO")
    logger.setLevel(level)
    if _configured:
        return logger

    log_dir = Path.home() / ".hashharvest" / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_dir / "hashharvest.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8"
        )
        file_handler.setFormatter(logging.Formatter(_FORMAT))
        logger.addHandler(file_handler)
    except OSError:
        # A read-only home (locked-down lab machine) must not stop the app —
        # fall back to console-only logging.
        pass

    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger.addHandler(console)
    logger.propagate = False
    _configured = True
    return logger


@contextmanager
def capture_logs(level=logging.INFO):
    """Yield a StringIO capturing all ``hashharvest`` log records emitted in the block.

    Temporarily lowers the logger level so INFO records are captured even when
    ``setup_logging`` has not been called (e.g. in tests).
    """
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(_FORMAT))
    logger = logging.getLogger(LOGGER_NAME)
    previous_level = logger.level
    if previous_level == logging.NOTSET or previous_level > level:
        logger.setLevel(level)
    logger.addHandler(handler)
    try:
        yield buffer
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
