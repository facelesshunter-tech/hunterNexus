"""Internet-wide asset intelligence and passive historical content
(scan-engine aggregation, direct Censys queries, plus urlscan.io).

Three sources, each a different kind of intelligence:

1. `uncover_search` -- wraps ProjectDiscovery's Uncover, which queries
   Shodan/Censys/FOFA/etc. through ONE interface rather than hand-rolling
   a separate client per search engine -- this is deliberately the
   consolidation layer recommended instead of wiring up FOFA/ZoomEye as
   separate low-priority modules.

2. `censys_search` -- a direct Censys API call for when you want Censys's
   own richer, structured host/cert data rather than Uncover's flattened
   multi-engine output.

3. `urlscan_search` / `urlscan_submit` -- urlscan.io's passive archive of
   previously-scanned pages (URLs, requests made, detected technology),
   a different kind of historical intelligence than Wayback/crt.sh:
   it's built from other researchers' and automated systems' prior scans
   of a domain, not just DNS/cert history.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run
from hunternexus.utils.http import get_json, post_json
from hunternexus.utils.dedupe import dedupe_strings

logger = logging.getLogger("hunternexus.internet_intel")

CENSYS_SEARCH_URL = "https://search.censys.io/api/v2/hosts/search"
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"

# Uncover keeps its OWN provider-config file, entirely separate from
# hunternexus's config.yaml -- confirmed live: a real Censys key sitting
# in hunternexus's own config does nothing for Uncover's -e censys engine
# unless it's also present here. Silent gap otherwise (0 results, no error
# telling you why), so uncover_search() syncs into it automatically below.
UNCOVER_PROVIDER_CONFIG = Path.home() / ".config" / "uncover" / "provider-config.yaml"


def sync_uncover_provider_config(config: Config, *, path: Path | None = None) -> None:
    """Propagates whatever Shodan/Censys credentials hunternexus has
    configured into Uncover's own provider-config.yaml, preserving every
    other provider entry already there untouched. Safe to call every time
    -- it's a small local file write, not a network call, and a no-op for
    any provider hunternexus has no key for."""
    path = path or UNCOVER_PROVIDER_CONFIG
    data: dict = {}
    if path.is_file():
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError:
            logger.warning("uncover provider-config at %s is not valid YAML -- leaving it untouched", path)
            return

    changed = False
    shodan_key = config.api_key("shodan")
    if shodan_key and data.get("shodan") != [shodan_key]:
        data["shodan"] = [shodan_key]
        changed = True
    censys_key = config.api_key("censys")
    if censys_key and ":" in censys_key:
        api_id, api_secret = censys_key.split(":", 1)
        censys_entry = f"{api_id}:{api_secret}"
        if data.get("censys") != [censys_entry]:
            data["censys"] = [censys_entry]
            changed = True

    if not changed:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(data, default_flow_style=False))
    logger.info("synced hunternexus's API keys into uncover's provider-config at %s", path)


def uncover_search(
    config: Config,
    query: str,
    *,
    engines: list[str] | None = None,
    limit: int = 100,
    timeout: int = 60,
) -> list[str]:
    """Queries multiple internet-scan engines through one CLI. `query` is
    typically the apex domain (e.g. `hostname:"example.com"` works across
    most of Uncover's supported engines' own query syntax) -- engines
    without a configured key are simply skipped by Uncover itself, no
    special handling needed here."""
    path = config.tool_path("uncover")
    if not path:
        logger.warning("uncover not found on PATH -- install with: go install github.com/projectdiscovery/uncover/cmd/uncover@latest")
        return []
    sync_uncover_provider_config(config)
    engines = engines or ["shodan", "censys"]
    argv = [path, "-silent", "-q", query, "-e", ",".join(engines), "-f", "ip:port", "-limit", str(limit)]
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("uncover exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return dedupe_strings(result.stdout.splitlines())


def censys_search(config: Config, query: str, *, per_page: int = 50) -> list[dict]:
    """Direct Censys Search API call. Requires a Censys Personal Access
    Token configured as config.api_keys.censys (format: "API_ID:SECRET"
    per Censys's own basic-auth convention)."""
    key = config.api_key("censys")
    if not key or ":" not in key:
        logger.warning(
            "no valid censys credentials configured (config.api_keys.censys, "
            "format 'API_ID:SECRET') -- censys_search skipped"
        )
        return []
    api_id, api_secret = key.split(":", 1)
    import requests

    try:
        resp = requests.get(
            CENSYS_SEARCH_URL,
            params={"q": query, "per_page": per_page},
            auth=(api_id, api_secret),
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.warning("censys search failed: %s", e)
        return []
    return data.get("result", {}).get("hits", [])


def urlscan_search(config: Config, domain: str, *, size: int = 100) -> list[dict]:
    """Search urlscan.io's public archive for prior scans of a domain --
    a free-tier API key works for search (submitting new scans needs a
    paid key for anything beyond public visibility)."""
    key = config.api_key("urlscan")
    headers = {"API-Key": key} if key else {}
    if not key:
        logger.info("no urlscan API key configured -- querying the public (unauthenticated, rate-limited) endpoint")
    data = get_json(URLSCAN_SEARCH_URL, params={"q": f"domain:{domain}", "size": size}, headers=headers, timeout=30)
    if not data:
        return []
    return data.get("results", [])


def urlscan_submit(config: Config, url: str, *, visibility: str = "unlisted") -> dict:
    """Submit a URL for a fresh urlscan.io scan. Requires an API key.
    `visibility` defaults to "unlisted" (not "public") so a scan of an
    in-scope-but-not-yet-public asset doesn't get indexed for everyone
    else to see -- deliberately NOT "private", since private scans
    require a paid plan and unlisted is the right default for a tool
    other people might run against programs they don't own."""
    key = config.api_key("urlscan")
    if not key:
        logger.warning("no urlscan API key configured (config.api_keys.urlscan) -- urlscan_submit skipped")
        return {}
    data = post_json(
        URLSCAN_SUBMIT_URL,
        json_body={"url": url, "visibility": visibility},
        headers={"API-Key": key},
        timeout=30,
    )
    return data or {}
