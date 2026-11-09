"""Deduplication helpers.

`sort -u` is the standard dedupe step after combining multiple subdomain
sources (Subfinder + Amass output concatenated). This module is the
programmatic equivalent, operating on Asset objects so that when the
*same* subdomain is found by two different techniques, both sources are
preserved in metadata rather than one silently overwriting the other --
useful later for the source-reliability scorecard idea.
"""

from __future__ import annotations

from typing import Iterable

from hunternexus.models import Asset


def dedupe_assets(assets: Iterable[Asset]) -> list[Asset]:
    merged: dict[str, Asset] = {}
    for asset in assets:
        k = asset.key()
        if k in merged:
            existing = merged[k]
            sources = set(existing.metadata.get("also_found_by", [existing.source.value]))
            sources.add(asset.source.value)
            existing.metadata["also_found_by"] = sorted(sources)
        else:
            asset.metadata.setdefault("also_found_by", [asset.source.value])
            merged[k] = asset
    return list(merged.values())


def dedupe_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        v = v.strip().lower()
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out
