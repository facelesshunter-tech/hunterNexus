"""ASN / IP-range discovery.

Finds the IP space and ASNs owned by a target, and digs into *related*
ASNs under the same parent org (e.g. a T-Mobile target turning up
related ASNs like T-FIBER and CLEARWIRE under the same ownership).

bgp.he.net is the natural starting point for this kind of lookup, with
Caduceus-via-Instant-Data-Scraper as a way to bulk-export its prefix
tables. bgp.he.net has no public API and aggressively rate-limits/blocks
scripted access, so instead of scraping it (fragile and likely to break
or get the tool blocked), this module implements the *same concept* --
ASN discovery and ASN-to-prefix expansion -- against two official, free,
no-key, stable public data APIs that return the same substantive data:

  - bgpview.io    : ASN/org keyword search, ASN detail, prefixes
  - stat.ripe.net : RIPEstat announced-prefixes data (authoritative, global)

This is a deliberate engineering substitution for a specific named tool,
documented here rather than silently done -- see docs/MODULE-MAP.md.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from hunternexus.utils.http import get_json

logger = logging.getLogger("hunternexus.asn_discovery")

BGPVIEW_BASE = "https://api.bgpview.io"
RIPESTAT_BASE = "https://stat.ripe.net/data"


@dataclass
class ASN:
    asn: str
    name: str
    description: str
    country: str = ""


def search_asns_by_keyword(keyword: str) -> list[ASN]:
    """The 'dig deeper into related ASNs under the same parent org' step --
    e.g. searching a company name to find every ASN mentioning it, not
    just the one obvious one."""
    data = get_json(f"{BGPVIEW_BASE}/search", params={"query_term": keyword})
    if not data or data.get("status") != "ok":
        logger.warning("bgpview search failed for %r", keyword)
        return []
    results: list[ASN] = []
    for a in data.get("data", {}).get("asns", []):
        results.append(
            ASN(
                asn=f"AS{a.get('asn')}",
                name=a.get("name", "") or "",
                description=a.get("description", "") or "",
                country=a.get("country_code", "") or "",
            )
        )
    return results


def asn_prefixes(asn: str) -> list[str]:
    """Expand a single ASN (e.g. 'AS46489') into its announced IPv4/IPv6
    prefixes, via RIPEstat (authoritative, global coverage, no key needed).
    This is the direct equivalent of reading bgp.he.net's 'Prefixes v4/v6'
    tables for an ASN."""
    asn_num = asn.upper().lstrip("AS")
    data = get_json(f"{RIPESTAT_BASE}/announced-prefixes/data.json", params={"resource": f"AS{asn_num}"})
    if not data:
        return []
    prefixes = []
    for p in data.get("data", {}).get("prefixes", []):
        prefix = p.get("prefix")
        if prefix:
            prefixes.append(prefix)
    return prefixes


def asn_detail(asn: str) -> dict:
    """Full org/holder info for an ASN -- used to confirm an ASN found via
    cert-pivot or reverse-DNS really belongs to the target org before
    trusting its IP ranges."""
    asn_num = asn.upper().lstrip("AS")
    data = get_json(f"{BGPVIEW_BASE}/asn/{asn_num}")
    if not data or data.get("status") != "ok":
        return {}
    return data.get("data", {})


def cloud_provider_ranges(provider: str) -> list[str]:
    """lord-alfred/ipranges-style cloud provider CIDR lists, used to
    scope a cert-pivot scan (see cert_pivot.py) to e.g. 'just AWS' rather
    than the whole internet. Pulls from each provider's own official
    published range file where one exists."""
    provider = provider.lower()
    if provider == "aws":
        data = get_json("https://ip-ranges.amazonaws.com/ip-ranges.json")
        if not data:
            return []
        return sorted({p["ip_prefix"] for p in data.get("prefixes", [])})
    if provider == "gcp":
        data = get_json("https://www.gstatic.com/ipranges/cloud.json")
        if not data:
            return []
        return sorted({p["ipv4Prefix"] for p in data.get("prefixes", []) if "ipv4Prefix" in p})
    if provider == "azure":
        logger.warning(
            "Azure publishes rotating signed-URL range files with no stable "
            "endpoint; download the current 'ServiceTags_Public' JSON manually "
            "from Microsoft's download center and pass it via --cloud-ranges-file."
        )
        return []
    if provider == "github":
        data = get_json("https://api.github.com/meta")
        if not data:
            return []
        out: list[str] = []
        for key in ("hooks", "web", "api", "git", "actions"):
            out.extend(data.get(key, []))
        return sorted(set(out))
    logger.warning("unknown cloud provider %r -- see lord-alfred/ipranges on GitHub for the full source list", provider)
    return []


def discover(target_keyword: str) -> dict:
    """End-to-end: keyword -> candidate ASNs -> expanded prefixes per ASN
    (find ASNs related to the org name, then pull prefixes for each)."""
    asns = search_asns_by_keyword(target_keyword)
    out = {}
    for a in asns:
        out[a.asn] = {
            "name": a.name,
            "description": a.description,
            "country": a.country,
            "prefixes": asn_prefixes(a.asn),
        }
    return out
