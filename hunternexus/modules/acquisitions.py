"""Acquisition / business-intel discovery.

New apex domains frequently enter scope through corporate acquisitions
-- a parent company's subsidiary or an acquired product line can carry
its own distinct infrastructure years after the deal closes. Four
sources are considered here: Crunchbase, Tracxn, Pitchbook, OCCRP Aleph.

Honest implementation note: Crunchbase's API requires a paid enterprise
agreement and a signed data license (not a simple API-key sign-up);
Tracxn, Pitchbook, and OCCRP Aleph are browse-only web tools with no
public API suitable for this use case at all. This module implements
Crunchbase as a best-effort wrapper that activates only if you have
enterprise API access configured, and documents the other three as
manual-research steps rather than pretending they can be automated --
consistent with what was flagged up front as not fully automatable.
"""

from __future__ import annotations

import logging

from hunternexus.config import Config
from hunternexus.utils.http import get_json

logger = logging.getLogger("hunternexus.acquisitions")

CRUNCHBASE_BASE = "https://api.crunchbase.com/api/v4"

MANUAL_RESEARCH_SOURCES = {
    "tracxn": "https://tracxn.com -- browse-only, no public API for this use case.",
    "pitchbook": "https://pitchbook.com -- enterprise subscription, browse-only.",
    "occrp_aleph": "https://aleph.occrp.org -- has a REST API (api.aleph.occrp.org) "
                   "for registered researchers; not wired up here because it requires "
                   "an individually-approved researcher account, not a self-serve key.",
}


def crunchbase_acquisitions(config: Config, org_permalink: str) -> list[dict]:
    """Requires an enterprise Crunchbase API key -- most hunters will not
    have one. Included for completeness / for anyone who does."""
    key = config.api_key("crunchbase")
    if not key:
        logger.warning(
            "no crunchbase API key configured (config.api_keys.crunchbase) -- "
            "this requires a paid enterprise Crunchbase agreement, not a free "
            "signup. See MANUAL_RESEARCH_SOURCES / docs/SETUP.md for the manual "
            "alternative (browse Crunchbase/Tracxn/Pitchbook/OCCRP Aleph by hand)."
        )
        return []
    data = get_json(
        f"{CRUNCHBASE_BASE}/entities/organizations/{org_permalink}/cards/acquiree_acquisitions",
        params={"user_key": key},
        timeout=30,
    )
    if not data:
        return []
    return data.get("cards", {}).get("acquiree_acquisitions", [])


SEC_API_SUBSIDIARIES_URL = "https://api.sec-api.io/mapping/subsidiaries"


def sec_api_subsidiaries(config: Config, company_name_or_cik: str) -> list[dict]:
    """sec-api.io pulls subsidiaries directly from SEC 10-K filing data --
    a primary-source alternative to Crunchbase/Tracxn/Pitchbook's curated
    databases. Requires a free-tier sec-api.io key (much lower barrier
    than Crunchbase's enterprise-only access)."""
    key = config.api_key("sec_api")
    if not key:
        logger.warning(
            "no sec-api.io key configured (config.api_keys.sec_api) -- "
            "subsidiary lookup skipped. Free-tier signup at sec-api.io."
        )
        return []
    data = get_json(SEC_API_SUBSIDIARIES_URL, params={"name": company_name_or_cik, "token": key}, timeout=30)
    if not data:
        return []
    return data.get("subsidiaries", []) if isinstance(data, dict) else data


def manual_research_checklist(org_name: str) -> dict[str, str]:
    """Not an automation -- a structured reminder of where to manually
    check for acquisitions, with direct search URLs, for the sources
    identified above that have no viable API."""
    return {
        "crunchbase_web": f"https://www.crunchbase.com/textsearch?q={org_name}",
        "tracxn": MANUAL_RESEARCH_SOURCES["tracxn"],
        "pitchbook": MANUAL_RESEARCH_SOURCES["pitchbook"],
        "occrp_aleph": f"https://aleph.occrp.org/search?q={org_name} ({MANUAL_RESEARCH_SOURCES['occrp_aleph']})",
    }
