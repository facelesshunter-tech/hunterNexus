"""Favicon analysis / COTS fingerprinting ("FavFreak" technique).

FavFreak (by Devansh Batham) fingerprints commercial-off-the-shelf
products by hashing their favicon and matching it against a database of
known product favicon hashes -- high-signal even when the rest of a
host's content is a blank/placeholder page.

Two modes, deliberately kept separate for honesty:

1. `run_favfreak`: shells out to the real favfreak.py if it's installed
   locally -- this uses FavFreak's own maintained hash database and is
   the recommended path.

2. `compute_hash` / `match_against_database`: a native reimplementation
   of the underlying technique (Shodan-style mmh3-of-base64-favicon
   hashing) for when FavFreak itself isn't installed, paired with a
   *user-supplied* fingerprint database file (config: `favicon_db_path`).
   hunternexus deliberately does NOT ship hardcoded "known product"
   hash values of its own -- getting a fingerprint hash wrong is worse
   than not fingerprinting at all, and FavFreak's own repository is the
   actual authoritative source for this data. See docs/SETUP.md for
   where to get one.
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run
from hunternexus.utils.http import USER_AGENT

logger = logging.getLogger("hunternexus.favicon_fingerprint")

try:
    import mmh3
except ImportError:  # pragma: no cover
    mmh3 = None  # type: ignore

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore


def run_favfreak(config: Config, urls_file: Path, output_dir: Path, *, timeout: int = 1800) -> Path:
    path = config.tool_path("favfreak") or config.tool_path("favfreak.py")
    if not path:
        logger.warning(
            "favfreak not found on PATH -- install from github.com/devanshbatham/FavFreak "
            "(falling back to compute_hash/match_against_database for native fingerprinting)"
        )
        return output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    stdin_urls = urls_file.read_text()
    run(["python3", path, "-o", str(output_dir)], stdin_text=stdin_urls, timeout=timeout)
    return output_dir


def compute_hash(url: str, *, timeout: int = 15) -> int | None:
    """Shodan-compatible favicon hash: mmh3.hash(base64(favicon_bytes)).
    Lets a computed hash be searched directly against Shodan
    (`http.favicon.hash:<value>`) even with no local fingerprint database
    at all."""
    if mmh3 is None or requests is None:
        logger.warning("mmh3 and/or requests not installed -- cannot compute favicon hash")
        return None
    favicon_url = url.rstrip("/") + "/favicon.ico"
    try:
        resp = requests.get(favicon_url, timeout=timeout, headers={"User-Agent": USER_AGENT})
    except requests.RequestException:
        return None
    if resp.status_code != 200 or not resp.content:
        return None
    encoded = base64.encodebytes(resp.content)
    return mmh3.hash(encoded)


def load_fingerprint_db(path: Path) -> dict[int, str]:
    """Expects a JSON file of {"<hash>": "product-name"}. Point this at
    FavFreak's own fingerprint data file, or a community-maintained
    favicon-hash list -- see docs/SETUP.md."""
    if not path.is_file():
        logger.warning("favicon fingerprint database not found at %s -- see docs/SETUP.md", path)
        return {}
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        logger.warning("could not parse favicon fingerprint database %s: %s", path, e)
        return {}
    return {int(k): v for k, v in raw.items()}


def match_against_database(url_hash_pairs: dict[str, int], db_path: Path) -> dict[str, str]:
    """Matches computed hashes against a locally-provided database.
    Returns {url: product_name} for every match found."""
    db = load_fingerprint_db(db_path)
    if not db:
        return {}
    return {url: db[h] for url, h in url_hash_pairs.items() if h in db}
