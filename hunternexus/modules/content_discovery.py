"""Directory/file content discovery (ffuf).

Closes a real gap: hunternexus could tell you a host was alive
(live_validation.py) but never probed *what's on it* beyond the root
page. ffuf fuzzes the FUZZ keyword in a URL against a wordlist -- used
here for directory/file discovery specifically (`-u <url>/FUZZ`).

Default wordlist points at SecLists (Discovery/Web-Content/common.txt)
when no explicit wordlist is given and SecLists happens to be installed
at the conventional `~/tools/SecLists` location -- otherwise the caller
must supply one. hunternexus deliberately doesn't vendor wordlists
itself (see wordlists/README.md's existing reasoning for the same call
made about subdomain bruteforce lists).
"""

from __future__ import annotations

import json
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run

logger = logging.getLogger("hunternexus.content_discovery")

DEFAULT_SECLISTS_WORDLIST = Path.home() / "tools" / "SecLists" / "Discovery" / "Web-Content" / "common.txt"


@dataclass
class FuzzHit:
    url: str
    status: int
    length: int
    words: int
    lines: int


def _resolve_wordlist(wordlist: Path | None) -> Path | None:
    if wordlist:
        return wordlist
    if DEFAULT_SECLISTS_WORDLIST.is_file():
        logger.info("no wordlist given -- defaulting to %s", DEFAULT_SECLISTS_WORDLIST)
        return DEFAULT_SECLISTS_WORDLIST
    return None


def fuzz(
    config: Config,
    base_url: str,
    *,
    wordlist: Path | None = None,
    threads: int = 40,
    match_codes: str = "200-299,301,302,307,401,403",
    extensions: list[str] | None = None,
    auto_calibrate: bool = True,
    timeout: int = 1800,
) -> list[FuzzHit]:
    path = config.tool_path("ffuf")
    if not path:
        logger.warning("ffuf not found on PATH -- install with: go install github.com/ffuf/ffuf/v2@latest")
        return []
    wl = _resolve_wordlist(wordlist)
    if not wl:
        logger.warning(
            "no wordlist available -- pass one explicitly, or install SecLists "
            "at ~/tools/SecLists (git clone https://github.com/danielmiessler/SecLists)"
        )
        return []

    target = base_url.rstrip("/") + "/FUZZ"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        out_path = Path(tmp.name)

    argv = [
        path,
        "-u", target,
        "-w", str(wl),
        "-t", str(threads),
        "-mc", match_codes,
        "-o", str(out_path),
        "-of", "json",
        "-s",  # silent -- suppress ffuf's own banner/progress noise, JSON file is the real output
    ]
    if extensions:
        argv += ["-e", ",".join(extensions)]
    if auto_calibrate:
        # -ac: ffuf probes a few random non-existent paths first and
        # auto-filters any response shape (status+size+words) that matches
        # them from the real results. Without this, a host that returns
        # the same status for every path (confirmed live: Akamai-fronted
        # API gateways blanket-403ing every FUZZ path) gets reported as a
        # near-total-wordlist "hit," which is noise, not a finding.
        argv.append("-ac")

    result = run(argv, timeout=timeout)
    hits: list[FuzzHit] = []
    if not out_path.is_file() or out_path.stat().st_size == 0:
        if not result.ok:
            logger.warning("ffuf exited %s: %s", result.returncode, result.stderr.strip()[:300])
        out_path.unlink(missing_ok=True)
        return []

    try:
        data = json.loads(out_path.read_text())
    except json.JSONDecodeError:
        logger.warning("ffuf produced unparseable JSON output")
        out_path.unlink(missing_ok=True)
        return []
    out_path.unlink(missing_ok=True)

    for r in data.get("results", []):
        hits.append(
            FuzzHit(
                url=r.get("url", ""),
                status=r.get("status", 0),
                length=r.get("length", 0),
                words=r.get("words", 0),
                lines=r.get("lines", 0),
            )
        )
    return hits
