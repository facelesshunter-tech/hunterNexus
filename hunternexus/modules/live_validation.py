"""Live-host validation and tech fingerprinting.

httpx is the tool of choice here for the first pass against any new
target: it's stable, reliable, and has a good amount of extensibility.
It does double duty as both the liveness checker and the
technology-fingerprinting tool (`-status-code -title -tech-detect`),
which is why there's no separate "technology identification" module --
this one covers it, running the equivalent of
`httpx -status-code -title -tech-detect -list sub_domains.txt`
against the resolved subdomain list.
"""

from __future__ import annotations

import json
import logging

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run
from hunternexus.models import LiveHost

logger = logging.getLogger("hunternexus.live_validation")


def probe(config: Config, hosts: list[str], *, timeout: int = 1800, threads: int = 50) -> list[LiveHost]:
    path = config.tool_path("httpx")
    if not path:
        logger.warning("httpx (projectdiscovery) not found on PATH -- install from github.com/projectdiscovery/httpx")
        return []
    argv = [
        path,
        "-silent",
        "-json",
        "-status-code",
        "-title",
        "-tech-detect",
        "-threads",
        str(threads),
    ]
    result = run(argv, stdin_text="\n".join(hosts), timeout=timeout)
    live: list[LiveHost] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        live.append(
            LiveHost(
                url=record.get("url", ""),
                status_code=record.get("status_code"),
                title=record.get("title"),
                tech=record.get("tech", []) or [],
            )
        )
    return live
