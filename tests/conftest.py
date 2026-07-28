"""Shared test fixtures."""

import tempfile
from pathlib import Path
from typing import Generator

import pytest

from reporeaver.config import RepoReaverConfig

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def config() -> RepoReaverConfig:
    return RepoReaverConfig(max_size_mb=5)


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    tmp = tempfile.mkdtemp(prefix="reporeaver_test_")
    try:
        yield Path(tmp)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES
