"""Reverse DNS.

Two distinct techniques, both implemented here:

1. PTR-record reverse lookup over an IP range (the hakrevdns technique):
   `prips <cidr> | hakrevdns` -> hostnames. Implemented natively via
   dnspython rather than shelling out, since this is pure DNS protocol
   work with no advantage to using an external binary.

2. Reverse DNS via shared DNS server: find every other domain that
   shares a target's custom nameserver, via whoisxmlapi.com's Reverse
   WHOIS API searching the NameServers field (POST to
   reverse-whois.whoisxmlapi.com/api/v2 with an advancedSearchTerms
   NameServers filter).
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import logging

import dns.resolver
import dns.reversename

from hunternexus.config import Config
from hunternexus.utils.http import post_json
from hunternexus.utils.dedupe import dedupe_strings

logger = logging.getLogger("hunternexus.reverse_dns")

WHOISXML_REVERSE_WHOIS_URL = "https://reverse-whois.whoisxmlapi.com/api/v2"


def _ptr_lookup(ip: str, resolver: dns.resolver.Resolver) -> str | None:
    try:
        rev_name = dns.reversename.from_address(ip)
        answer = resolver.resolve(rev_name, "PTR")
        return str(answer[0]).rstrip(".")
    except Exception:
        return None


def bulk_ptr_lookup(cidr: str, *, resolvers: list[str] | None = None, max_workers: int = 50) -> dict[str, str]:
    """hakrevdns-equivalent: reverse-resolve every host in a CIDR. Returns
    {ip: hostname} for only the IPs that actually have a PTR record."""
    resolver = dns.resolver.Resolver()
    if resolvers:
        resolver.nameservers = resolvers
    resolver.timeout = 2
    resolver.lifetime = 2

    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        logger.warning("invalid CIDR %r", cidr)
        return {}

    results: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_ptr_lookup, str(ip), resolver): str(ip) for ip in net.hosts()}
        for fut in concurrent.futures.as_completed(futures):
            ip = futures[fut]
            hostname = fut.result()
            if hostname:
                results[ip] = hostname
    return results


def get_nameservers(domain: str, *, resolvers: list[str] | None = None) -> list[str]:
    """`dig +short ns <domain>` equivalent -- the first step of the
    shared-nameserver pivot technique."""
    resolver = dns.resolver.Resolver()
    if resolvers:
        resolver.nameservers = resolvers
    try:
        answers = resolver.resolve(domain, "NS")
        return dedupe_strings(str(r).rstrip(".") for r in answers)
    except Exception as e:
        logger.warning("NS lookup for %s failed: %s", domain, e)
        return []


def domains_sharing_nameserver(config: Config, nameserver: str) -> list[str]:
    """Asks 'what other domains use this nameserver?' via whoisxmlapi's
    Reverse WHOIS API. Noisy when the nameserver is a shared/CDN one
    (Akamai, Cloudflare, etc.) rather than a dedicated custom
    nameserver -- the follow-up step there is to eyeball or grep the
    results down to what's actually relevant."""
    key = config.api_key("whoisxmlapi")
    if not key:
        logger.warning(
            "no whoisxmlapi API key configured (config.api_keys.whoisxmlapi) -- "
            "shared-nameserver pivot skipped."
        )
        return []
    body = {
        "apiKey": key,
        "searchType": "current",
        "mode": "purchase",
        "advancedSearchTerms": [{"field": "NameServers", "term": nameserver}],
    }
    data = post_json(WHOISXML_REVERSE_WHOIS_URL, json_body=body, timeout=60)
    if not data:
        return []
    return dedupe_strings(data.get("domainsList", []))


def shared_nameserver_pivot(config: Config, domain: str, *, resolvers: list[str] | None = None) -> dict[str, list[str]]:
    """End-to-end: domain -> its nameservers -> every other domain sharing
    each one. Returns {nameserver: [domains]}."""
    out: dict[str, list[str]] = {}
    for ns in get_nameservers(domain, resolvers=resolvers):
        out[ns] = domains_sharing_nameserver(config, ns)
    return out
