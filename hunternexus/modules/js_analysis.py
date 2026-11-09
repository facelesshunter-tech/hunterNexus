"""JavaScript analysis: endpoint extraction, secret discovery, and source
map recovery.

Three techniques, run against the JS files/URLs that web_crawl.py's
katana_crawl() (with -jc) and the pipeline's crawl stage surface:

- `xnlinkfinder_extract` -- pulls endpoint paths out of JS (the modern,
  actively-maintained successor to LinkFinder). Verified to require
  file-based output (`-o <path>`), NOT `-o cli` -- xnLinkFinder's own
  help text warns cli mode is "not piped to another program," which was
  confirmed directly: piping its cli-mode output produced nothing at all
  under subprocess capture.
- `secretfinder_extract` -- pulls likely secrets (API keys, tokens,
  credentials) out of JS. SecretFinder only ever produces an HTML report
  (not JSON), so this module parses the `.container` divs it wraps each
  finding in -- a deliberate, documented parsing choice, not an
  assumption.
- `discover_source_maps` -- native implementation of the ShrinkRay /
  SourceMapper idea (user asked to pick one; built natively instead, same
  reasoning already established elsewhere in this project for CSP/
  crossdomain.xml parsing: this is well-defined, simple protocol work
  with no real advantage to wrapping a specific external tool whose exact
  current GitHub repo wasn't independently confirmed, avoiding a repeat
  of the earlier github-subdomains wrong-repo mistake). Finds
  `//# sourceMappingURL=` comments in JS, fetches the referenced .map
  file, and extracts the original source file paths from its standard
  Source Map v3 `sources` array.
"""

from __future__ import annotations

import logging
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run
from hunternexus.utils.http import USER_AGENT
from hunternexus.utils.dedupe import dedupe_strings

logger = logging.getLogger("hunternexus.js_analysis")

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

SOURCEMAP_COMMENT_RE = re.compile(r"//[@#]\s*sourceMappingURL=(\S+)")


def xnlinkfinder_extract(config: Config, target: str, *, scope_filter: str, timeout: int = 300) -> list[str]:
    """`target` can be a single URL, or a local file of URLs (one per
    line, e.g. the output of katana_crawl() written to disk).
    `scope_filter` is mandatory in current xnLinkFinder versions -- pass
    the apex domain to avoid crawling/reporting out-of-scope links."""
    path = config.tool_path("xnLinkFinder") or config.tool_path("xnlinkfinder")
    if not path:
        logger.warning("xnLinkFinder not found on PATH -- install with: pip install xnLinkFinder")
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        out_path = Path(tmp.name)

    argv = [path, "-i", target, "-sf", scope_filter, "-o", str(out_path), "-nb"]
    result = run(argv, timeout=timeout)
    links: list[str] = []
    if out_path.is_file():
        links = [l.strip() for l in out_path.read_text().splitlines() if l.strip()]
        out_path.unlink(missing_ok=True)
    elif not result.ok:
        logger.warning("xnLinkFinder exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return dedupe_strings(links)


@dataclass
class SecretHit:
    context: str  # the raw text block SecretFinder reported the match in


def secretfinder_extract(config: Config, js_url: str, *, timeout: int = 120) -> list[SecretHit]:
    """SecretFinder has no JSON/plain-text output mode -- confirmed
    directly -- only an HTML report where each finding is wrapped in a
    `<div class="container">...</div>` block. Parsed with a regex rather
    than adding a full HTML-parsing dependency for one tool."""
    path = config.tool_path("secretfinder") or config.tool_path("SecretFinder")
    if not path:
        logger.warning("secretfinder not found on PATH -- install from github.com/m4ll0k/SecretFinder")
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as tmp:
        out_path = Path(tmp.name)

    argv = [path, "-i", js_url, "-o", str(out_path)]
    result = run(argv, timeout=timeout)
    hits: list[SecretHit] = []
    if out_path.is_file():
        html = out_path.read_text(errors="replace")
        for block in re.findall(r'<div class=[\'"]container[\'"][^>]*>(.*?)</div>', html, re.DOTALL):
            text = re.sub(r"<[^>]+>", " ", block).strip()
            if text:
                hits.append(SecretHit(context=text))
        out_path.unlink(missing_ok=True)
    elif not result.ok:
        logger.warning("secretfinder exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return hits


def discover_source_maps(js_urls: list[str], *, timeout: int = 15) -> dict[str, list[str]]:
    """For each JS file URL, look for a `sourceMappingURL` comment,
    fetch the referenced .map file, and return the original source file
    paths listed in its `sources` array -- often reveals the project's
    real file/directory structure, unminified variable names, and
    sometimes files never meant to be shipped at all. Returns
    {js_url: [source_paths]} for every JS file where a usable map was
    actually found."""
    if requests is None:
        logger.warning("requests not installed -- cannot discover source maps")
        return {}
    out: dict[str, list[str]] = {}
    for js_url in js_urls:
        try:
            resp = requests.get(js_url, timeout=timeout, headers={"User-Agent": USER_AGENT})
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue
        match = SOURCEMAP_COMMENT_RE.search(resp.text[-2000:])  # the comment is always near the end of the file
        if not match:
            continue
        map_ref = match.group(1).strip()
        if map_ref.startswith("data:"):
            continue  # inline base64 source map, not a separate fetchable file
        map_url = map_ref if map_ref.startswith("http") else _join_url(js_url, map_ref)
        try:
            map_resp = requests.get(map_url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            map_resp.raise_for_status()
            map_data = map_resp.json()
        except Exception:
            continue
        sources = map_data.get("sources", [])
        if sources:
            out[js_url] = sources
    return out


def _join_url(base: str, relative: str) -> str:
    import urllib.parse

    return urllib.parse.urljoin(base, relative)
