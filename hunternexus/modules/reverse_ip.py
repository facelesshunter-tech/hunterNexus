"""Reverse IP / virtual-host co-hosting lookup.

Reverse IP/domain lookup to virtual hosts, backlinks, and redirects,
via the host.io API: co-hosted domains sharing an IP/ASN, inbound
backlinks, and domains that redirect to the target.
"""

from __future__ import annotations

import logging

from hunternexus.config import Config
from hunternexus.utils.http import get_json
from hunternexus.utils.dedupe import dedupe_strings

logger = logging.getLogger("hunternexus.reverse_ip")

HOSTIO_BASE = "https://host.io/api"


def _request(config: Config, path: str, params: dict | None = None) -> dict | None:
    token = config.api_key("hostio")
    if not token:
        logger.warning("no host.io API token configured (config.api_keys.hostio) -- reverse IP lookup skipped")
        return None
    p = dict(params or {})
    p["token"] = token
    return get_json(f"{HOSTIO_BASE}/{path}", params=p, timeout=30)


def domain_summary(config: Config, domain: str) -> dict:
    """URL, IP, ASN, country, server header, DNS records for a domain --
    the base lookup everything else pivots from."""
    data = _request(config, f"full/{domain}")
    return data or {}


def co_hosted_domains(config: Config, domain: str) -> list[str]:
    """Other domains sharing the same IP (same ASN/virtual-hosting
    neighborhood) -- e.g. a company's regional TLD variants
    (example.com / example.de / example.co.uk) often co-resolve."""
    summary = domain_summary(config, domain)
    web = summary.get("web", {})
    ip = web.get("ip")
    if not ip:
        return []
    data = _request(config, f"domains/ip/{ip}")
    if not data:
        return []
    return dedupe_strings(d.get("domain", "") for d in data.get("domains", []))


def backlinks(config: Config, domain: str) -> list[str]:
    """Domains that link to the target -- OSINT/phishing-infrastructure
    value, and occasionally reveals partner/subsidiary sites."""
    data = _request(config, f"domains/link/{domain}")
    if not data:
        return []
    return dedupe_strings(d.get("domain", "") for d in data.get("domains", []))


def redirects_to(config: Config, domain: str) -> list[str]:
    """Domains that redirect to the target -- often brand-protection
    registrations (e.g. a company's own .social or .careers domains),
    each itself a legitimate, in-scope-adjacent apex domain."""
    data = _request(config, f"domains/redirect/{domain}")
    if not data:
        return []
    return dedupe_strings(d.get("domain", "") for d in data.get("domains", []))
