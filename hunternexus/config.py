"""Central configuration loader.

Every API-gated source has a slot here (see config/config.example.yaml).
A module checks `Config.has(name)` before attempting to use a gated
source, and degrades gracefully (skips with a warning) rather than
crashing when a key is missing -- hunternexus is meant to be useful on
day one with zero keys configured, and to get progressively more
powerful as you add keys, prioritized roughly in this order: Chaos ->
GitHub tokens -> Shodan -> free/cheap -> paid.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Optional

import yaml

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "hunternexus" / "config.yaml"


class Config:
    def __init__(self, data: dict[str, Any], path: Optional[Path] = None):
        self._data = data
        self.path = path

    # ---- loading -----------------------------------------------------

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        candidates = []
        if path:
            candidates.append(Path(path))
        candidates.append(Path.cwd() / "config" / "config.yaml")
        candidates.append(DEFAULT_CONFIG_PATH)

        for candidate in candidates:
            if candidate and candidate.is_file():
                with open(candidate, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                return cls(data, path=candidate)

        # No config found -- run with an empty config rather than failing.
        # Every module must tolerate this (free-tier sources + installed
        # binaries still work with zero keys configured).
        return cls({}, path=None)

    # ---- API keys ------------------------------------------------------

    def api_key(self, source: str) -> Optional[str]:
        """Look up a single API key, preferring environment variables over
        the config file so secrets never have to live on disk if you
        don't want them to: HUNTERNEXUS_<SOURCE>_API_KEY.

        For a source configured as a list (github's token pool), this
        returns the first non-blank entry rather than the raw list --
        callers that specifically want the full pool must use
        api_keys_list() instead."""
        env_name = f"HUNTERNEXUS_{source.upper()}_API_KEY"
        if env_name in os.environ:
            return os.environ[env_name]
        value = (self._data.get("api_keys", {}) or {}).get(source)
        if isinstance(value, list):
            for v in value:
                if isinstance(v, str) and v.strip():
                    return v
            return None
        if isinstance(value, str) and not value.strip():
            return None
        return value

    def api_keys_list(self, source: str) -> list[str]:
        """Some sources (GitHub tokens especially -- a *pool* of tokens is
        recommended so you can round-robin around rate limits) support
        multiple keys. Blank placeholder entries (the "" values
        config.example.yaml ships for every unfilled slot) are filtered
        out here, not just left for callers to deal with -- a list
        containing only empty strings must behave as "nothing configured",
        not as a non-empty list of blanks."""
        keys = (self._data.get("api_keys", {}) or {}).get(source)
        if keys is None:
            single = self.api_key(source)
            return [single] if single else []
        if isinstance(keys, str):
            return [keys] if keys.strip() else []
        return [k for k in keys if isinstance(k, str) and k.strip()]

    def has(self, source: str) -> bool:
        """True iff there is at least one real (non-blank) value configured
        for this source, whether it's a single-key or list-valued source.
        Deliberately does NOT just check truthiness of api_key()/
        api_keys_list()'s return values directly -- a non-empty Python list
        of blank strings is still "nothing configured" here."""
        return bool(self.api_keys_list(source))

    # ---- external tool binaries ----------------------------------------

    def tool_path(self, tool: str) -> Optional[str]:
        """Resolve an external binary: explicit config override, else PATH."""
        override = (self._data.get("tools", {}) or {}).get(tool)
        if override:
            return override
        return shutil.which(tool)

    def tool_available(self, tool: str) -> bool:
        return self.tool_path(tool) is not None

    # ---- generic settings ------------------------------------------------

    def get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self._data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    @property
    def resolvers_path(self) -> Optional[str]:
        return self.get("recon", "resolvers_path", default=None)

    @property
    def output_dir(self) -> Path:
        d = self.get("recon", "output_dir", default="./hunternexus-output")
        return Path(d)
