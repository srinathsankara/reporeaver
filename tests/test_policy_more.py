"""Additional policy tests — YAML validation errors."""

import pytest
from reporeaver.policy import load_policy


class TestLoadPolicyValidation:
    def test_invalid_yaml_not_dict(self, tmp_path):
        f = tmp_path / "policy.yaml"
        f.write_text("[1, 2, 3]")
        with pytest.raises(ValueError, match="must contain a mapping"):
            load_policy(str(f))

    def test_invalid_threshold(self, tmp_path):
        f = tmp_path / "policy.yaml"
        f.write_text("severity_threshold: ultra\nblock_categories: []\nallow_paths: []\n")
        with pytest.raises(ValueError, match="severity_threshold"):
            load_policy(str(f))

    def test_invalid_block_categories_type(self, tmp_path):
        f = tmp_path / "policy.yaml"
        f.write_text("severity_threshold: high\nblock_categories: bad\nallow_paths: []\n")
        with pytest.raises(ValueError, match="block_categories must be a list"):
            load_policy(str(f))

    def test_invalid_allow_paths_type(self, tmp_path):
        f = tmp_path / "policy.yaml"
        f.write_text("severity_threshold: high\nblock_categories: []\nallow_paths: bad\n")
        with pytest.raises(ValueError, match="allow_paths must be a list"):
            load_policy(str(f))
