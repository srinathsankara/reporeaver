"""Minimal structured logging."""

import logging
import os
import sys
from pathlib import Path

_LOG_DIR = Path.home() / ".reporeaver"


def setup_logging(verbose: bool = False) -> logging.Logger:
    _LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("reporeaver")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    fh = logging.FileHandler(str(_LOG_DIR / "scan.log"), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    if verbose or os.environ.get("REPOREAVER_VERBOSE"):
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger


def get_logger(name: str = "reporeaver") -> logging.Logger:
    return setup_logging()
