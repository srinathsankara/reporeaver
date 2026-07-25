"""Minimal structured logging."""

import logging
import os
import sys
from pathlib import Path
from typing import Optional

_LOG_DIR = Path.home() / ".reporeaver"
_LOG: Optional[logging.Logger] = None


def get_logger(name: str = "reporeaver") -> logging.Logger:
    global _LOG
    if _LOG is not None:
        return _LOG

    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("reporeaver")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    fh = logging.FileHandler(str(_LOG_DIR / "scan.log"), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    if os.environ.get("REPOREAVER_VERBOSE"):
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.WARNING)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    _LOG = logger
    return logger
