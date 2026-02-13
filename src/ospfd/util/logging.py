"""Logging configuration for ospfd."""

from __future__ import annotations

import logging
import sys
from typing import Optional


def setup_logging(
    level: str = "info",
    log_file: Optional[str] = None,
    name: str = "ospfd",
) -> logging.Logger:
    """Configure logging for the OSPF daemon.

    Args:
        level: Log level string (debug, info, warning, error).
        log_file: Optional file path. If None, logs to stderr.
        name: Logger name.

    Returns:
        The configured root logger for ospfd.
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if log_file:
        handler = logging.FileHandler(log_file)
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
