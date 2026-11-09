"""API route/endpoint brute-forcing (Kiterunner).

Kiterunner's `-A` flag fetches a named wordlist live from Assetnote's
hosted service (`wordlist.assetnote.io`) -- its documented default. That
host turned out to be DNS-unreachable from this project's own dev
sandbox (confirmed directly), which took the whole stage offline with it
every time. Rather than hard-depend on that one host being reachable,
this module defaults to building and using a small LOCAL `.kite`
wordlist instead, compiled once from SecLists' own API-route lists via
`kr kb convert` (confirmed directly: `-w` requires the compiled `.kite`
protobuf format, but `kr kb convert <txt> <kite>` happily builds one from
any plain text wordlist -- no dependency on Assetnote's specific hosted
JSON schema at all). Assetnote's bigger, continuously-updated hosted list
remains available as an explicit opt-in (`use_assetnote_hosted=True`) for
environments with normal internet access to it.

IMPORTANT automation-safety finding, verified directly: without
`--kitebuilder-full-scan`, kr's default two-phase scan behavior asks an
interactive `[y/n]` terminal prompt ("Continue Scanning with full
wordlist?") when its first phase finds nothing -- which would hang a
subprocess call indefinitely with no TTY to answer it. This module
always passes `--kitebuilder-full-scan` for exactly that reason.

The per-route HIT record shape (method/url/status_code/content_length)
is now confirmed against a real positive match, scanned with the local
wordlist against a live target -- no longer just an inference from
Kiterunner's documented convention.
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run

logger = logging.getLogger("hunternexus.api_discovery")

DEFAULT_WORDLIST = "apiroutes-210228"

# SecLists ships several API-route lists of wildly varying quality (some
# are clean path lists, some are tokenized junk from static analysis) --
# these two are the clean ones: curated endpoint paths, no symbol/operator
# noise.
DEFAULT_LOCAL_WORDLIST_SOURCES = [
    Path.home() / "tools" / "SecLists" / "Discovery" / "Web-Content" / "api" / "api-endpoints.txt",
    Path.home() / "tools" / "SecLists" / "Discovery" / "Web-Content" / "common-api-endpoints-mazen160.txt",
]
LOCAL_KITE_WORDLIST = Path.home() / ".cache" / "hunternexus" / "api-routes-local.kite"
_ROUTE_LINE_RE = re.compile(r"^[A-Za-z0-9_\-./{}]+$")


def build_local_kite_wordlist(
    config: Config,
    *,
    source_files: list[Path] | None = None,
    out_path: Path | None = None,
    force: bool = False,
) -> Path | None:
    """Compiles a local, fully-offline .kite wordlist from SecLists' own
    API-route lists -- cached at `out_path` and only rebuilt when missing
    or `force=True`, so this is a one-time cost per machine, not a
    per-scan one."""
    out_path = out_path or LOCAL_KITE_WORDLIST
    if out_path.is_file() and not force:
        return out_path

    path = config.tool_path("kr") or config.tool_path("kiterunner")
    if not path:
        logger.warning("kiterunner (kr) not found on PATH -- cannot build local API-route wordlist")
        return None

    sources = [p for p in (source_files or DEFAULT_LOCAL_WORDLIST_SOURCES) if p.is_file()]
    if not sources:
        logger.warning(
            "no local API wordlist source files found -- install SecLists at "
            "~/tools/SecLists (git clone https://github.com/danielmiessler/SecLists)"
        )
        return None

    lines: set[str] = set()
    for src in sources:
        for line in src.read_text(errors="replace").splitlines():
            line = line.strip()
            if line and _ROUTE_LINE_RE.match(line) and any(c.isalpha() for c in line):
                lines.add(line)
    if not lines:
        return None

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write("\n".join(sorted(lines)))
        txt_path = Path(tmp.name)

    result = run([path, "kb", "convert", str(txt_path), str(out_path)], timeout=120)
    txt_path.unlink(missing_ok=True)
    if not out_path.is_file():
        logger.warning("kr kb convert failed to produce a .kite file: %s", result.stderr.strip()[:300])
        return None
    logger.info("built local API-route wordlist (%d routes) at %s", len(lines), out_path)
    return out_path


@dataclass
class APIRouteHit:
    method: str
    target: str
    path: str
    status_code: int | None = None
    content_length: int | None = None

    @property
    def url(self) -> str:
        return self.target.rstrip("/") + self.path


def scan(
    config: Config,
    target: str,
    *,
    wordlist: str = DEFAULT_WORDLIST,
    max_wordlist_lines: int | None = 20000,
    custom_kite_file: str | None = None,
    use_assetnote_hosted: bool = False,
    timeout: int = 1800,
) -> list[APIRouteHit]:
    """Scans one host for API routes. By default, uses a local
    automatically-built .kite wordlist (see build_local_kite_wordlist())
    rather than Assetnote's hosted one -- pass `custom_kite_file` to use a
    specific pre-compiled .kite file instead, or `use_assetnote_hosted=True`
    to opt into Assetnote's bigger, continuously-updated hosted list (needs
    working DNS/connectivity to wordlist.assetnote.io)."""
    path = config.tool_path("kr") or config.tool_path("kiterunner")
    if not path:
        logger.warning(
            "kiterunner (kr) not found on PATH -- download a release binary from "
            "github.com/assetnote/kiterunner (no clean `go install` path -- "
            "it ships prebuilt releases instead)"
        )
        return []

    argv = [path, "scan", target, "-o", "json", "-q", "--kitebuilder-full-scan"]
    if custom_kite_file:
        argv += ["-w", custom_kite_file]
    elif use_assetnote_hosted:
        wl_spec = f"{wordlist};{max_wordlist_lines}" if max_wordlist_lines else wordlist
        argv += ["-A", wl_spec]
    else:
        local_kite = build_local_kite_wordlist(config)
        if not local_kite:
            logger.warning("no local API-route wordlist available -- skipping kiterunner scan for %s", target)
            return []
        argv += ["-w", str(local_kite)]

    result = run(argv, timeout=timeout)
    hits: list[APIRouteHit] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Skip the info/status lines (shape: has "level" and "message"
        # keys, no "path") -- only keep actual per-route hit records.
        # Real shape, confirmed live against a genuine positive match
        # (httpbin.org/get): {"method","target","path","responses":[{"uri","sc","len"}],"time"}
        # -- NOT the originally-guessed flat {"url","status_code","content_length"}.
        # The old flat-key filter never matched a single real hit record,
        # silently discarding every genuine finding this module ever produced.
        if "path" not in record:
            continue
        responses = record.get("responses") or [{}]
        first = responses[0]
        hits.append(
            APIRouteHit(
                method=record.get("method", ""),
                target=record.get("target", ""),
                path=record.get("path", ""),
                status_code=first.get("sc"),
                content_length=first.get("len"),
            )
        )
    if not result.ok and not hits:
        logger.warning("kiterunner exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return hits
