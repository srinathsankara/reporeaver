"""Auto-discovery of reporeaver.yaml config files.

Load order:
  1. ./reporeaver.yaml (project root)
  2. ./.reporeaver.yaml (dotfile variant)
  3. ~/.config/reporeaver/config.yaml (user global)
  4. CLI args (override all)
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

CONFIG_PATHS = [
    "reporeaver.yaml",
    ".reporeaver.yaml",
    str(Path.home() / ".config" / "reporeaver" / "config.yaml"),
]


def discover_config(target_dir: Optional[str] = None) -> Dict[str, Any]:
    """Find and load the nearest config file. Returns parsed dict or empty."""
    search_dirs = []
    if target_dir:
        search_dirs.append(Path(target_dir))
    search_dirs.append(Path.cwd())
    search_dirs.append(Path.home())

    for base in search_dirs:
        for name in CONFIG_PATHS:
            p = base / name
            if p.exists():
                try:
                    return _load_yaml(p)
                except Exception:
                    pass
    return {}


def _load_yaml(path: Path) -> Dict[str, Any]:
    import yaml
    with open(path) as f:
        return yaml.safe_load(f) or {}


def merge_config(cli_args: Dict[str, Any], file_config: Dict[str, Any]) -> Dict[str, Any]:
    """CLI args override file config for any key present in both."""
    result = dict(file_config)
    result.update({k: v for k, v in cli_args.items() if v is not None})
    return result
