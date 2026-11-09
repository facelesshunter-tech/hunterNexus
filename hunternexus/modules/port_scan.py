"""Port / service discovery.

Three active scanners are supported here, each with a different
strength: naabu (most usable), rustscan (fastest), and nmap (most
extensible), plus SMAP as a passive, Shodan-API-backed drop-in nmap
replacement for stealthy recon with no packets sent to the target at
all. naabu is used as the default since it offers the best general
usability; the others are exposed for when their specific strength
(raw speed, or deep service/version detection) is what's needed.
"""

from __future__ import annotations

import logging

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run

logger = logging.getLogger("hunternexus.port_scan")


def naabu_scan(config: Config, targets: list[str], *, top_ports: int = 1000, timeout: int = 1800) -> list[str]:
    path = config.tool_path("naabu")
    if not path:
        logger.warning("naabu not found on PATH -- install from github.com/projectdiscovery/naabu")
        return []
    argv = [path, "-silent", "-top-ports", str(top_ports)]
    result = run(argv, stdin_text="\n".join(targets), timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("naabu exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def rustscan_scan(config: Config, target: str, *, timeout: int = 300) -> list[str]:
    path = config.tool_path("rustscan")
    if not path:
        logger.warning("rustscan not found on PATH -- install from github.com/RustScan/RustScan")
        return []
    result = run([path, "-a", target, "--", "-sV"], timeout=timeout)
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def smap_scan(config: Config, target: str, *, timeout: int = 60) -> str:
    """Passive port scan via Shodan's own indexed data -- zero packets
    sent to the target. Requires a Shodan API key."""
    path = config.tool_path("smap")
    key = config.api_key("shodan")
    if not path:
        logger.warning("smap not found on PATH -- install from github.com/s0md3v/Smap")
        return ""
    if not key:
        logger.warning("no shodan API key configured (config.api_keys.shodan) -- smap needs one to query Shodan's index")
        return ""
    result = run([path, target], timeout=timeout)
    return result.stdout
