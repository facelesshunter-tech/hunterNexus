"""Shared HTTP client helper for the API-based modules (reverse WHOIS, DMARC
pivot, reverse DNS via shared-nameserver, reverse IP, acquisitions, etc.).

Centralizing this gives every API-based module consistent timeouts, a
descriptive User-Agent (good citizenship for third-party free-tier APIs),
and one place to add retry/backoff later.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import requests

logger = logging.getLogger("hunternexus.http")

USER_AGENT = "hunternexus/0.1 (+https://github.com/facelesshunter-tech/hunternexus)"


def get_json(
    url: str,
    *,
    params: Optional[dict[str, Any]] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 30,
) -> Optional[dict[str, Any]]:
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    try:
        resp = requests.get(url, params=params, headers=hdrs, timeout=timeout)
    except requests.RequestException as e:
        logger.warning("request to %s failed: %s", url, e)
        return None
    if resp.status_code != 200:
        logger.warning("request to %s returned HTTP %s", url, resp.status_code)
        return None
    try:
        return resp.json()
    except ValueError:
        logger.warning("request to %s did not return JSON", url)
        return None


def strip_scheme(url: str) -> str:
    """`https://host.example.com:8443/path` -> `host.example.com`. Used
    everywhere a tool needs a bare hostname (dnsx, tlsx) but the pipeline
    only has full httpx-style URLs on hand (LiveHost.url)."""
    return url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]


def post_json(
    url: str,
    *,
    json_body: Optional[dict[str, Any]] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: int = 30,
) -> Optional[dict[str, Any]]:
    hdrs = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    try:
        resp = requests.post(url, json=json_body, headers=hdrs, timeout=timeout)
    except requests.RequestException as e:
        logger.warning("request to %s failed: %s", url, e)
        return None
    if resp.status_code != 200:
        logger.warning("request to %s returned HTTP %s", url, resp.status_code)
        return None
    try:
        return resp.json()
    except ValueError:
        return None
