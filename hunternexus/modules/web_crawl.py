"""Web crawling and historical URL mining (Katana, GAU).

The gap flagged earliest and most repeatedly across this whole project:
hunternexus could tell you a host was alive, but never actually crawled
*into* it to find real endpoints. Two complementary techniques:

- `katana_crawl` -- active, JS-aware crawling of a *live* host right now
  (`-jc` parses endpoints out of JS files it encounters, not just HTML
  links) -- only run this against hosts live_validation.py already
  confirmed are up, same "don't waste a stage on dead hosts" discipline
  dns_intel.py's filtering exists for.
- `gau_historical` -- passive, no live traffic to the target at all:
  pulls every URL ever seen for a domain across Wayback Machine,
  CommonCrawl, OTX, and urlscan.io's own archives. Finds old/forgotten
  endpoints that current crawling never would, because they're not
  linked from the live site anymore.

Both feed the same downstream stages: js_analysis.py (secrets/endpoints
inside the JS files these two surface) and parameter_discovery.py
(hidden params on the endpoints these two surface).
"""

from __future__ import annotations

import logging

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run
from hunternexus.utils.dedupe import dedupe_strings

logger = logging.getLogger("hunternexus.web_crawl")


def katana_crawl(
    config: Config,
    hosts: list[str],
    *,
    depth: int = 2,
    js_crawl: bool = True,
    known_files: str = "all",  # katana's -kf takes exactly one of: all, robotstxt, sitemapxml -- NOT a comma-combo (verified)
    timeout: int = 1800,
) -> list[str]:
    """Crawls a list of already-confirmed-live hosts. Plain (non-JSONL)
    output mode is used deliberately -- JSONL mode includes full
    request/response bodies per URL, which is far more data than this
    module needs (just the discovered URL list) and meaningfully slower
    to produce and parse at scale."""
    path = config.tool_path("katana")
    if not path:
        logger.warning("katana not found on PATH -- install with: go install github.com/projectdiscovery/katana/cmd/katana@latest")
        return []
    argv = [path, "-silent", "-d", str(depth)]
    if js_crawl:
        argv.append("-jc")
    if known_files:
        argv += ["-kf", known_files]
    result = run(argv, stdin_text="\n".join(hosts), timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("katana exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return dedupe_strings(result.stdout.splitlines())


def gau_historical(
    config: Config,
    domain: str,
    *,
    include_subs: bool = True,
    providers: list[str] | None = None,
    threads: int = 10,  # gau defaults to 1, which is meaningfully slow once --subs expands scope to every subdomain
    timeout: int = 900,
) -> list[str]:
    path = config.tool_path("gau")
    if not path:
        logger.warning("gau not found on PATH -- install with: go install github.com/lc/gau/v2/cmd/gau@latest")
        return []
    argv = [path, "--threads", str(threads)]
    if include_subs:
        argv.append("--subs")
    if providers:
        argv += ["--providers", ",".join(providers)]
    argv.append(domain)
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("gau exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return dedupe_strings(result.stdout.splitlines())
