"""Tests for logging setup."""

import logging

from reporeaver.logging import get_logger, setup_logging


class TestLogging:
    def test_setup_returns_logger(self):
        logger = setup_logging(verbose=True)
        assert logger.name == "reporeaver"
        assert logger.level == logging.DEBUG

    def test_setup_verbose_console_debug(self):
        logger = setup_logging(verbose=True)
        handlers = logger.handlers
        console = [h for h in handlers if isinstance(h, logging.StreamHandler)]
        assert len(console) >= 1
        assert console[0].level == logging.DEBUG

    def test_get_logger_works(self):
        logger = get_logger()
        assert logger.name == "reporeaver"
        assert logger.level == logging.DEBUG

    def test_setup_idempotent(self):
        logger1 = setup_logging()
        logger2 = setup_logging()
        assert logger1 is logger2
