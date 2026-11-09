"""DNS intelligence / bulk resolution enrichment (dnsx).

This sits between "raw candidate subdomain list" (from subdomain_passive +
subdomain_bruteforce + permutation, after dedupe) and "live host probing"
(httpx) in the senior-methodology pipeline ordering: before spending time
screenshotting/crawling/fuzzing a host, confirm it actually resolves, and
pull its record data (A/AAAA/CNAME/MX/TXT/NS) in bulk, in one pass, rather
than relying on httpx's liveness check alone -- httpx tells you "is there
a web server here," dnsx tells you "does this name even exist, and what
does it point to," which is the cheaper, earlier-stage question to ask
first. It also filters out wildcard-DNS false positives (a single
`*.example.com` wildcard record would otherwise make every bruteforce/
permutation guess look like it "resolved"), which is exactly the kind of
noise puredns's own wildcard-detection threading handles for bruteforce
but doesn't retroactively clean up candidates that arrived from *other*
sources (passive scraping, GitHub, AI guesses).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run

logger = logging.getLogger("hunternexus.dns_intel")


@dataclass
class DNSRecord:
    host: str
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)

    def resolves(self) -> bool:
        return bool(self.a or self.aaaa or self.cname)


def resolve_bulk(
    config: Config,
    hosts: list[str],
    *,
    resolvers: str | None = None,
    filter_wildcards: bool = True,
    threads: int = 100,
    timeout: int = 900,
) -> dict[str, DNSRecord]:
    """One dnsx pass over the whole candidate list, requesting every
    record type at once (`-a -aaaa -cname -mx -txt -ns`) plus wildcard
    filtering via `-auto-wildcard` (not `-wd`, which needs one explicit
    apex domain -- `-auto-wildcard` detects per-host automatically, which
    is what a bulk, potentially-multi-apex candidate list needs).
    Returns {host: DNSRecord} for every host dnsx returned data for;
    hosts with no record data of any kind (i.e. don't actually exist)
    are simply absent from the result, which is the signal callers should
    use to drop them before any further-stage processing."""
    path = config.tool_path("dnsx")
    if not path:
        logger.warning("dnsx not found on PATH -- install with: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest")
        return {}

    argv = [path, "-silent", "-json", "-a", "-aaaa", "-cname", "-mx", "-txt", "-ns", "-t", str(threads)]
    if resolvers:
        argv += ["-r", resolvers]
    if filter_wildcards:
        argv.append("-auto-wildcard")

    result = run(argv, stdin_text="\n".join(hosts), timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("dnsx exited %s: %s", result.returncode, result.stderr.strip()[:300])
        return {}

    out: dict[str, DNSRecord] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = record.get("host", "")
        if not host:
            continue
        existing = out.get(host, DNSRecord(host=host))
        existing.a.extend(record.get("a", []) or [])
        existing.aaaa.extend(record.get("aaaa", []) or [])
        existing.cname.extend(record.get("cname", []) or [])
        existing.mx.extend(record.get("mx", []) or [])
        existing.txt.extend(record.get("txt", []) or [])
        existing.ns.extend(record.get("ns", []) or [])
        out[host] = existing
    return out


def resolving_hosts_only(records: dict[str, DNSRecord]) -> list[str]:
    """The practical filter step: drop every candidate that dnsx confirmed
    doesn't actually resolve, before handing the list to httpx/katana/ffuf
    -- no sense crawling or fuzzing a name that isn't even live in DNS."""
    return [host for host, rec in records.items() if rec.resolves()]
