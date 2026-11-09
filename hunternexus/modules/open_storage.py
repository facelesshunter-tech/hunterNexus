"""Open/misconfigured cloud storage discovery.

Two complementary techniques:

1. Greyhatwarfare -- indexes publicly-exposed, misconfigured cloud
   storage buckets (S3, Azure Blob, GCS, DigitalOcean Spaces) others
   have already found and crawled, via a documented search API.

2. cloud_enum -- actively brute-forces bucket/storage-account names
   across AWS/Azure/GCP for a given keyword (typically the org name and
   common mutations of it), rather than searching an existing index --
   finds buckets Greyhatwarfare's crawler never happened to discover.
   Directly closes a real gap flagged earlier in this project ("Cloud_enum
   -- strongly recommended, you already have it installed but not wired
   in"). Log-entry JSON shape ({"access", "msg", "target"}) confirmed
   directly from cloud_enum's own source (enum_tools/utils.py's
   fmt_output()), since live-testing a true positive wasn't practical in
   a sandboxed environment with no real matching cloud resources to find.
"""

from __future__ import annotations

import json
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path

from hunternexus.config import Config
from hunternexus.utils.http import get_json
from hunternexus.utils.subprocess_runner import run

logger = logging.getLogger("hunternexus.open_storage")

GREYHATWARFARE_BASE = "https://buckets.grayhatwarfare.com/api/v2"


def search_buckets(config: Config, keyword: str, *, limit: int = 100) -> list[dict]:
    key = config.api_key("greyhatwarfare")
    if not key:
        logger.warning("no greyhatwarfare API key configured (config.api_keys.greyhatwarfare) -- bucket search skipped")
        return []
    data = get_json(
        f"{GREYHATWARFARE_BASE}/files",
        params={"keywords": keyword, "limit": limit},
        headers={"Authorization": f"Bearer {key}"},
        timeout=30,
    )
    if not data:
        return []
    return data.get("files", [])


def search_bucket_names(config: Config, keyword: str, *, limit: int = 100) -> list[str]:
    """Search for bucket *names* containing a keyword, rather than files
    inside buckets -- useful for finding e.g. `<company>-backups` or
    `<company>-prod` style bucket-naming patterns directly."""
    key = config.api_key("greyhatwarfare")
    if not key:
        logger.warning("no greyhatwarfare API key configured (config.api_keys.greyhatwarfare) -- bucket search skipped")
        return []
    data = get_json(
        f"{GREYHATWARFARE_BASE}/buckets",
        params={"keywords": keyword, "limit": limit},
        headers={"Authorization": f"Bearer {key}"},
        timeout=30,
    )
    if not data:
        return []
    return [b.get("bucket", "") for b in data.get("buckets", []) if b.get("bucket")]


@dataclass
class CloudEnumHit:
    access: str  # "public", "protected", or "disabled"
    msg: str
    target: str


def cloud_enum_scan(
    config: Config,
    keyword: str,
    *,
    quickscan: bool = True,
    disable_providers: list[str] | None = None,
    timeout: int = 1800,
) -> list[CloudEnumHit]:
    """Brute-forces AWS/Azure/GCP storage/service names built from
    `keyword` and its common mutations. `quickscan=True` (default) skips
    the slower mutation-expansion and second-level scans -- set False for
    a thorough pass once you've confirmed the keyword is worth the extra
    time."""
    path = config.tool_path("cloud_enum")
    if not path:
        logger.warning("cloud_enum not found on PATH -- install from github.com/initstring/cloud_enum")
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        out_path = Path(tmp.name)

    argv = [path, "-k", keyword, "-l", str(out_path), "-f", "json"]
    if quickscan:
        argv.append("-qs")
    for provider in disable_providers or []:
        flag = {"aws": "--disable-aws", "azure": "--disable-azure", "gcp": "--disable-gcp"}.get(provider.lower())
        if flag:
            argv.append(flag)

    result = run(argv, timeout=timeout)
    hits: list[CloudEnumHit] = []
    if out_path.is_file():
        for line in out_path.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "target" in record:
                hits.append(
                    CloudEnumHit(
                        access=record.get("access", ""),
                        msg=record.get("msg", ""),
                        target=record.get("target", ""),
                    )
                )
        out_path.unlink(missing_ok=True)
    elif not result.ok:
        logger.warning("cloud_enum exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return hits
