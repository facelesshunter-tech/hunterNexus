"""Shared data model used across every pipeline stage.

Keeping one common Asset shape is what lets stages "feed forward" into
each other (e.g. RevWHOIS -> httpx, GitHub recon -> subdomain list ->
resolver, dnsgen output -> puredns).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class AssetType(str, Enum):
    APEX_DOMAIN = "apex_domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    URL = "url"
    GITHUB_HIT = "github_hit"
    CERTIFICATE = "certificate"


class Source(str, Enum):
    """Which technique produced this asset. Mirrors the module/technique name."""

    SEED = "seed"
    ASN_DISCOVERY = "asn_discovery"
    CERT_PIVOT = "cert_pivot"
    REVERSE_WHOIS = "reverse_whois"
    REVERSE_DNS = "reverse_dns"
    REVERSE_IP = "reverse_ip"
    DMARC_PIVOT = "dmarc_pivot"
    ACQUISITIONS = "acquisitions"
    AI_RECON = "ai_recon"
    SUBDOMAIN_PASSIVE = "subdomain_passive"  # generic/legacy value -- prefer the per-tool values below so the source-reliability scorecard can actually distinguish them
    SUBFINDER = "subfinder"
    AMASS = "amass"
    BBOT = "bbot"
    ASSETFINDER = "assetfinder"
    CRTSH = "crtsh"
    C99 = "c99"
    SUBDOMAIN_BRUTEFORCE = "subdomain_bruteforce"
    PERMUTATION = "permutation"
    GITHUB_RECON = "github_recon"
    VHOST_SCAN = "vhost_scan"
    PORT_SCAN = "port_scan"
    LIVE_VALIDATION = "live_validation"
    SCREENSHOT = "screenshot"
    FAVICON_FINGERPRINT = "favicon_fingerprint"
    CSP_MISC = "csp_misc"


@dataclass
class Asset:
    value: str
    asset_type: AssetType
    source: Source
    target: str  # the apex domain / program this asset belongs to
    discovered_at: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    def key(self) -> str:
        """Dedupe key: same value+type is the same asset regardless of source."""
        return f"{self.asset_type.value}:{self.value.lower().strip()}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["asset_type"] = self.asset_type.value
        d["source"] = self.source.value
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Asset":
        return Asset(
            value=d["value"],
            asset_type=AssetType(d["asset_type"]),
            source=Source(d["source"]),
            target=d["target"],
            discovered_at=d.get("discovered_at", time.time()),
            metadata=d.get("metadata", {}),
        )


@dataclass
class LiveHost:
    """Enriched asset once httpx/screenshotting/fingerprinting has run on it."""

    url: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    tech: list[str] = field(default_factory=list)
    favicon_hash: Optional[str] = None
    favicon_match: Optional[str] = None
    screenshot_path: Optional[str] = None
    risk_score: float = 0.0
    risk_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
