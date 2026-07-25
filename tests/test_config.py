"""Tests for config file auto-discovery."""

from reporeaver.config import discover_config, merge_config


def test_discover_config_none(tmp_path):
    cfg = discover_config(str(tmp_path))
    assert cfg == {}


def test_merge_config_cli_overrides():
    cli = {"verbose": True, "max_size_mb": 5.0}
    file_cfg = {"verbose": False, "policy": "my-policy.yaml"}
    merged = merge_config(cli, file_cfg)
    assert merged["verbose"] is True  # CLI wins
    assert merged["max_size_mb"] == 5.0
    assert merged["policy"] == "my-policy.yaml"  # from file


def test_merge_config_empty_cli():
    cli = {"verbose": None}
    file_cfg = {"verbose": True}
    merged = merge_config(cli, file_cfg)
    assert merged["verbose"] is True  # file_cfg used when cli is None
