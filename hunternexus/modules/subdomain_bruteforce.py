"""Active subdomain brute-forcing.

Wraps puredns rather than massdns directly -- puredns is a wrapper and
feature enhancer around massdns, so using it directly keeps the
invocation simple: `puredns bruteforce <wordlist> <domain> -r resolvers.txt`.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run
from hunternexus.utils.dedupe import dedupe_strings

logger = logging.getLogger("hunternexus.subdomain_bruteforce")

# puredns prints its own fatal errors (most notably "massdns not found" when
# that dependency is missing) to STDOUT, not stderr -- confirmed directly by
# running it with massdns absent. Without this check, that error text gets
# silently treated as "discovered subdomains" (confirmed live: it corrupted
# a real engagement's asset database with puredns's own error message,
# counted as 3 real subdomain hits). Every genuine puredns output line is a
# resolved hostname and will always look like one; anything that doesn't is
# rejected and logged loudly instead of silently accepted.
_HOSTNAME_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def _valid_hostnames_only(lines: list[str]) -> list[str]:
    valid, rejected = [], []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        (valid if _HOSTNAME_RE.match(line) else rejected).append(line)
    if rejected:
        logger.warning(
            "puredns produced %d line(s) that don't look like real hostnames -- discarded, not treated as "
            "subdomains (likely puredns's own error output, e.g. a missing massdns dependency): %s",
            len(rejected), rejected[:3],
        )
    return valid

# trickest/resolvers is the fresh-resolver-list source used here;
# resolvers-trusted.txt is the one to use for re-validating results
# obtained against the (noisier) public resolver list.
TRICKEST_RESOLVERS_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
TRICKEST_RESOLVERS_TRUSTED_URL = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt"


def fetch_resolvers(dest: Path, *, trusted: bool = False) -> Path:
    import requests

    url = TRICKEST_RESOLVERS_TRUSTED_URL if trusted else TRICKEST_RESOLVERS_URL
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    dest.write_text(resp.text)
    return dest


def bruteforce(
    config: Config,
    domain: str,
    wordlist: Path,
    resolvers: Path,
    *,
    timeout: int = 1800,
) -> list[str]:
    path = config.tool_path("puredns")
    if not path:
        logger.warning("puredns not found on PATH -- install from github.com/d3mondev/puredns")
        return []
    argv = [path, "bruteforce", str(wordlist), domain, "-r", str(resolvers), "-q"]
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("puredns exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return dedupe_strings(_valid_hostnames_only(result.stdout.splitlines()))


def resolve(
    config: Config,
    candidates: list[str],
    resolvers: Path,
    *,
    timeout: int = 1800,
) -> list[str]:
    """`puredns resolve` -- used by the permutation module to validate
    dnsgen/alterx-generated candidate names, matching the standard pipeline
    shape: `cat subdomains.txt | dnsgen - | puredns resolve --resolvers resolvers.txt`."""
    path = config.tool_path("puredns")
    if not path:
        logger.warning("puredns not found on PATH -- install from github.com/d3mondev/puredns")
        return []
    argv = [path, "resolve", "--resolvers", str(resolvers), "-q"]
    result = run(argv, stdin_text="\n".join(candidates), timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("puredns resolve exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return dedupe_strings(_valid_hostnames_only(result.stdout.splitlines()))
