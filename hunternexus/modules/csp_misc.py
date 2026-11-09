"""Additional recon metadata sources: CSP header mining, crossdomain.xml,
and historical JS/HTML via Waymore.

CSP and crossdomain.xml parsing are implemented natively (no external
tool needed, both are a single HTTP request + simple parsing). Waymore
is wrapped as an external tool since it does its own archive-crawling
logic that isn't worth reimplementing.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
import xml.etree.ElementTree as ET

from hunternexus.config import Config
from hunternexus.utils.http import USER_AGENT
from hunternexus.utils.subprocess_runner import run
from hunternexus.utils.dedupe import dedupe_strings

logger = logging.getLogger("hunternexus.csp_misc")

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

DOMAIN_RE = re.compile(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")


def extract_csp_domains(url: str, *, timeout: int = 15) -> list[str]:
    """csprecon-equivalent: fetch a page, read its Content-Security-Policy
    header, pull out every referenced domain -- these are domains the site
    itself explicitly trusts (CDNs, APIs, asset hosts); e.g. for
    github.com this surfaces opengraph.githubassets.com,
    uploads.github.com, api.github.com, etc."""
    if requests is None:
        logger.warning("requests not installed -- cannot fetch CSP header")
        return []
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
    except requests.RequestException as e:
        logger.warning("failed to fetch %s for CSP extraction: %s", url, e)
        return []
    csp = resp.headers.get("Content-Security-Policy", "")
    if not csp:
        return []
    domains = []
    for token in csp.replace(";", " ").split():
        if token.startswith("http://") or token.startswith("https://"):
            parsed = urllib.parse.urlparse(token)
            if parsed.netloc:
                domains.append(parsed.netloc)
        elif "." in token and not token.startswith(("'", "data:", "blob:")):
            domains.append(token.lstrip("*."))
    return dedupe_strings(domains)


def extract_crossdomain_xml(base_url: str, *, timeout: int = 15) -> list[str]:
    """Legacy Flash-era crossdomain.xml -- explicitly lists domains
    permitted to make cross-domain requests to this site; occasionally
    still present and useful as a same-organization domain list."""
    if requests is None:
        return []
    url = base_url.rstrip("/") + "/crossdomain.xml"
    try:
        resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
    except requests.RequestException:
        return []
    if resp.status_code != 200 or not resp.content:
        return []
    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError:
        return []
    domains = []
    for allow in root.findall(".//allow-access-from"):
        domain = allow.get("domain")
        if domain:
            domains.append(domain.lstrip("*."))
    return dedupe_strings(domains)


def waymore_historical(config: Config, domain: str, *, timeout: int = 1800) -> list[str]:
    """Pulls historical JS/HTML references via Waymore, to find old
    subdomain/API references no longer linked from the live site."""
    path = config.tool_path("waymore")
    if not path:
        logger.warning("waymore not found on PATH -- install from github.com/xnl-h4ck3r/waymore")
        return []
    argv = [path, "-i", domain, "-mode", "U"]
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("waymore exited %s: %s", result.returncode, result.stderr.strip()[:300])
    urls = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    hosts = []
    for u in urls:
        m = DOMAIN_RE.match(u)
        if m:
            hosts.append(m.group(1))
    return dedupe_strings(hosts)
