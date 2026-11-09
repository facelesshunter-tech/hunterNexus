"""VHost (virtual host) scanning.

A single IP can silently answer for hostnames that were never surfaced by
DNS/subdomain enumeration, distinguished only by the HTTP Host header.
This module wraps VHostScan (codingo/VHostScan), which is effective at
finding the real vhost among several identically-responding decoys.
"""

from __future__ import annotations

import logging

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run

logger = logging.getLogger("hunternexus.vhost_scan")


def scan(
    config: Config,
    target_ip: str,
    wordlist: str | None = None,
    *,
    base_host: str | None = None,
    timeout: int = 1800,
) -> str:
    """Runs VHostScan against a target IP. `base_host` lets VHostScan
    detect catch-all/wildcard responses by comparing against a known-good
    baseline vhost -- this is what separates the real vhost from decoys
    that return identical content hashes."""
    path = config.tool_path("VHostScan")
    if not path:
        logger.warning("VHostScan not found on PATH -- install with: pip install VHostScan")
        return ""
    argv = [path, "-t", target_ip]
    if wordlist:
        argv += ["-w", wordlist]
    if base_host:
        argv += ["-b", base_host]
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("VHostScan exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return result.stdout
