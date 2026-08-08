"""
Authorized Discovery Config — runtime policy for the extension.

Loads ~/.config/program-intelligence/authorized_discovery.json (JSON, no
comments) if present; otherwise falls back to built-in defaults. The
source-of-truth file (with comments) lives at
config/authorized_discovery.jsonc in the platform repo and is synced here.

All values are additive policy knobs — the extension works out of the box
without this file.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("program-intelligence.config")

DATA_DIR = Path.home() / ".config" / "program-intelligence"
CONFIG_PATH = DATA_DIR / "authorized_discovery.json"

DEFAULTS: dict[str, Any] = {
    "providers": {
        "hackerone": {"enabled": True},
        "bugcrowd": {"enabled": True},
        "intigriti": {"enabled": True},
        "yeswehack": {"enabled": True},
        "securitytxt": {"enabled": True},
        "cache_ttl": 86400,
    },
    "fingerprinting": {
        "enabled": True,
        "max_plugin_probes": 10,
        "max_theme_probes": 5,
        "timeout": 10,
        "require_authorization": True,
    },
    "policy": {
        "read_only_discovery": True,
        "passive_fingerprinting": True,
    },
}

_config: dict[str, Any] | None = None


def load_config(force_reload: bool = False) -> dict[str, Any]:
    """Load the runtime authorized-discovery config (cached)."""
    global _config
    if _config is not None and not force_reload:
        return _config

    merged = json.loads(json.dumps(DEFAULTS))  # deep copy
    if CONFIG_PATH.exists():
        try:
            loaded = json.loads(CONFIG_PATH.read_text())
            _deep_merge(merged, loaded)
            logger.info("Loaded authorized_discovery config from %s", CONFIG_PATH)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("authorized_discovery config load failed: %s — using defaults", exc)
    else:
        logger.info("No authorized_discovery config at %s — using defaults", CONFIG_PATH)

    _config = merged
    return _config


def _deep_merge(base: dict, override: dict) -> None:
    """Recursively merge override into base (override wins)."""
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def provider_enabled(name: str) -> bool:
    """Whether a provider is enabled by policy."""
    cfg = load_config()
    return bool(cfg["providers"].get(name, {}).get("enabled", True))


def fingerprinting_config() -> dict[str, Any]:
    """Fingerprinting policy block."""
    return load_config()["fingerprinting"]
