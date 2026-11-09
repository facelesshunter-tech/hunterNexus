"""Permutation / alteration scanning.

Generates structural variants of already-known subdomains (dev1/dev2,
dev-1/dev-2, dev.1/dev.2 patterns) that a flat wordlist brute-force can't
find, then resolves them -- the same pipeline as:
`cat subdomains.txt | dnsgen - | puredns resolve --resolvers resolvers.txt`.

Both dnsgen and the newer alterx (Project Discovery) are supported;
dnsgen is tried first as the more established of the two, with alterx
as the named alternative.
"""

from __future__ import annotations

import logging
from pathlib import Path

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run
from hunternexus.utils.dedupe import dedupe_strings
from hunternexus.modules.subdomain_bruteforce import resolve as puredns_resolve

logger = logging.getLogger("hunternexus.permutation")


def generate_dnsgen(config: Config, known_subdomains: list[str]) -> list[str]:
    path = config.tool_path("dnsgen")
    if not path:
        logger.warning("dnsgen not found on PATH -- install with: pip install dnsgen")
        return []
    result = run([path, "-"], stdin_text="\n".join(known_subdomains), timeout=300)
    return dedupe_strings(result.stdout.splitlines())


def generate_alterx(config: Config, known_subdomains: list[str]) -> list[str]:
    path = config.tool_path("alterx")
    if not path:
        logger.warning("alterx not found on PATH -- install from github.com/projectdiscovery/alterx")
        return []
    result = run([path, "-silent"], stdin_text="\n".join(known_subdomains), timeout=300)
    return dedupe_strings(result.stdout.splitlines())


def permute_and_resolve(
    config: Config,
    known_subdomains: list[str],
    resolvers: Path,
    *,
    engine: str = "dnsgen",
) -> list[str]:
    """Generates candidate permutations with the chosen engine, then
    resolves them with puredns -- dnsgen on its own only generates names,
    it does NOT resolve them."""
    if engine == "alterx":
        candidates = generate_alterx(config, known_subdomains)
    else:
        candidates = generate_dnsgen(config, known_subdomains)
    if not candidates:
        return []
    return puredns_resolve(config, candidates, resolvers)
