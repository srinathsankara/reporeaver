"""Minimal structured logging. Replaces bare print() throughout."""

import logging
import os
import sys
from pathlib import Path
from typing import Optional

_LOG: Optional[logging.Logger] = None
_LOG_DIR = Path.home() / ".reporeaver"


def get_logger(name: str = "reporeaver") -> logging.Logger:
    global _LOG
    if _LOG is not None:
        return _LOG

    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("reporeaver")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    # File handler — always on, captures everything
    fh = logging.FileHandler(str(_LOG_DIR / "scan.log"), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # Console handler — controlled by REPOREAVER_VERBOSE env or debug flag
    ch = logging.StreamHandler(sys.stdout)
    if os.environ.get("REPOREAVER_VERBOSE"):
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    _LOG = logger
    return logger


def get_console_logger() -> logging.Logger:
    """Logger that only writes WARNING+ to console, full to file."""
    return get_logger()
