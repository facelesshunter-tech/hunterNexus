"""Scoped vulnerability verification (Nuclei) -- for ONE job only:
confirming the edge-device CVEs scoring/prioritize.py already flags by
tech-stack guess, not general-purpose vulnerability scanning.

This is the one deliberate exception carved out of an otherwise firm
"vulnerability scanning doesn't belong in a recon tool" position (see the
project's own tool-category assessment: hunternexus is a crawler/
discovery tool, not a scanner). The distinction that makes this
acceptable: `verify_watchlist()` only ever runs the EXACT nuclei template
IDs matching scoring.prioritize.EDGE_DEVICE_CVE_WATCHLIST's CVE list --
never a tag-based, severity-based, or default full-template-library scan.
It answers "is the thing we already suspect actually true," not "what
else might be wrong here."

Nuclei's JSONL schema (template-id/info/matched-at/host) is treated as
reliably documented and stable -- it's the same ProjectDiscovery JSONL
convention hunternexus already parses from httpx -- unlike a couple of
this session's newer/rarer integrations (Kiterunner) where the exact
schema genuinely wasn't independently confirmable here.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run
from hunternexus.scoring.prioritize import EDGE_DEVICE_CVE_WATCHLIST

logger = logging.getLogger("hunternexus.vuln_verify")


@dataclass
class VerifiedFinding:
    template_id: str
    host: str
    matched_at: str
    severity: str
    name: str


def verify_watchlist(config: Config, hosts: list[str], *, timeout: int = 1800) -> list[VerifiedFinding]:
    """Runs nuclei against `hosts`, restricted to exactly the CVE IDs in
    the edge-device watchlist -- call this on hosts
    scoring.prioritize.score_host() already flagged as matching one of
    those products, not on your whole host list indiscriminately."""
    path = config.tool_path("nuclei")
    if not path:
        logger.warning("nuclei not found on PATH -- install from github.com/projectdiscovery/nuclei")
        return []
    if not hosts:
        return []

    all_cves = sorted({cve for cves in EDGE_DEVICE_CVE_WATCHLIST.values() for cve in cves})
    # -duc (disable update check): nuclei's default startup update-check is
    # a network call that can add significant latency (confirmed directly:
    # an identical scan went from ~12s to a 55s+ timeout without this flag)
    # -- undesirable for a non-interactive automation tool regardless of
    # the exact cause, and firmly correct for a scoped verification pass
    # that shouldn't silently update templates mid-run anyway.
    argv = [path, "-id", ",".join(all_cves), "-jsonl", "-silent", "-duc"]
    result = run(argv, stdin_text="\n".join(hosts), timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("nuclei exited %s: %s", result.returncode, result.stderr.strip()[:300])

    findings: list[VerifiedFinding] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = record.get("info", {})
        findings.append(
            VerifiedFinding(
                template_id=record.get("template-id", ""),
                host=record.get("host", ""),
                matched_at=record.get("matched-at", ""),
                severity=info.get("severity", ""),
                name=info.get("name", ""),
            )
        )
    return findings
