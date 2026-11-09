"""DMARC analysis / shared-DMARC-record pivoting.

Companies frequently centralize DMARC reporting under one third-party
identifier (e.g. a shared `rua=mailto:<id>@ag.dmarcian.com` address)
across every domain/subdomain they own. Finding that shared identifier
lets you pivot to every other domain using it.

Two distinct capabilities:

1. `get_dmarc_record` / `shared_identifier_across_known_subdomains`:
   pure DNS, no API key needed -- this is the dmarc-subdomains
   (Tedixx) tool's actual technique applied to a list of subdomains you
   already have (from subdomain_passive/subdomain_bruteforce), grouping
   them by identical DMARC reporting identifier.

2. `reverse_search_by_identifier`: finding *new, previously-unknown*
   domains across the internet sharing that identifier requires a
   DNS/TXT-record-reverse-search service (dmarc.live and dmarcly.com are
   consumer web tools with no clean bulk API for this; SecurityTrails'
   DNS search API is used here as the closest real equivalent, since it
   supports structured DNS-record search). Marked best-effort: the exact
   request shape for this specific use case should be verified against
   SecurityTrails' current docs before relying on it in production, since
   this was implemented from documented API patterns rather than a live
   test against a paid account.
"""

from __future__ import annotations

import logging
import re

import dns.resolver

from hunternexus.config import Config
from hunternexus.utils.http import post_json

logger = logging.getLogger("hunternexus.dmarc_pivot")

IDENTIFIER_RE = re.compile(r"rua=mailto:([^@]+)@", re.IGNORECASE)

SECURITYTRAILS_SEARCH_URL = "https://api.securitytrails.com/v1/search/dns"


def get_dmarc_record(domain: str, *, resolvers: list[str] | None = None) -> str | None:
    resolver = dns.resolver.Resolver()
    if resolvers:
        resolver.nameservers = resolvers
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            text = b"".join(rdata.strings).decode("utf-8", errors="ignore")
            if text.lower().startswith("v=dmarc1"):
                return text
    except Exception:
        return None
    return None


def extract_reporting_identifier(dmarc_record: str) -> str | None:
    """Pull the unique identifier out of `rua=mailto:<id>@provider.com` --
    this is the value that's shared/compared across domains, not the full
    record (policy flags like p=reject/pct=100 are often identical across
    unrelated companies using the same provider's defaults and are not a
    useful comparison key on their own)."""
    match = IDENTIFIER_RE.search(dmarc_record)
    return match.group(1) if match else None


def shared_identifier_across_known_subdomains(
    subdomains: list[str], *, resolvers: list[str] | None = None
) -> dict[str, list[str]]:
    """Group a list of already-known subdomains by shared DMARC reporting
    identifier -- no API key required. Returns {identifier: [subdomains]}.
    A group with more than one member confirms those subdomains are
    managed under the same centralized DMARC configuration."""
    groups: dict[str, list[str]] = {}
    for sub in subdomains:
        record = get_dmarc_record(sub, resolvers=resolvers)
        if not record:
            continue
        identifier = extract_reporting_identifier(record)
        if not identifier:
            continue
        groups.setdefault(identifier, []).append(sub)
    return groups


def reverse_search_by_identifier(config: Config, identifier: str) -> list[str]:
    """Best-effort: find other domains across the internet sharing this
    DMARC reporting identifier via SecurityTrails' DNS search API. Requires
    a SecurityTrails key with DNS-search scope. Explicitly noisy -- this
    technique needs manual eyeball/grep filtering afterward, since the
    reporting provider often serves many unrelated customers too."""
    key = config.api_key("securitytrails")
    if not key:
        logger.warning(
            "no securitytrails API key configured (config.api_keys.securitytrails) -- "
            "DMARC reverse-identifier search skipped."
        )
        return []
    body = {"filter": {"txt": identifier}}
    data = post_json(
        SECURITYTRAILS_SEARCH_URL,
        json_body=body,
        headers={"APIKEY": key},
        timeout=60,
    )
    if not data:
        return []
    return [r.get("hostname", "") for r in data.get("records", []) if r.get("hostname")]
