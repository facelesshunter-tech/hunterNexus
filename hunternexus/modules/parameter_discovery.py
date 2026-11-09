"""Hidden HTTP parameter discovery (Arjun, x8).

Both added by request, deliberately together rather than picking one --
they use different techniques (Arjun: wordlist-based brute force with
response-diffing; x8: Rust-based, faster, with reflected-parameter and
page-comparison modes, plus a header-discovery mode Arjun doesn't have),
so running both against a confirmed-interesting endpoint (not every
endpoint -- see pipeline.py's staging discipline) genuinely finds more
than either alone, with the pipeline's dedupe layer collapsing the
overlap.

Direct gap-filler: finding `?debug=true` or `?role=admin` style hidden
parameters is a cornerstone of IDOR/BOLA and mass-assignment testing,
and hunternexus had no parameter-discovery capability at all before
this module.
"""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run
from hunternexus.utils.dedupe import dedupe_strings

logger = logging.getLogger("hunternexus.parameter_discovery")


def arjun_discover(config: Config, url: str, *, method: str = "GET", timeout: int = 600) -> list[str]:
    path = config.tool_path("arjun")
    if not path:
        logger.warning("arjun not found on PATH -- install with: pip install arjun")
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        out_path = Path(tmp.name)

    argv = [path, "-u", url, "-m", method, "-oJ", str(out_path), "-q"]
    result = run(argv, timeout=timeout)
    params: list[str] = []
    if out_path.is_file() and out_path.stat().st_size > 0:
        try:
            data = json.loads(out_path.read_text())
            # arjun's JSON shape is {url: {param: value, ...}}
            for url_key, found in data.items():
                if isinstance(found, dict):
                    params.extend(found.keys())
        except json.JSONDecodeError:
            logger.warning("arjun produced unparseable JSON output")
        out_path.unlink(missing_ok=True)
    elif not result.ok:
        logger.warning("arjun failed against %s: %s", url, _describe_arjun_failure(result.stderr))
    return dedupe_strings(params)


# A real, reproducible bug in arjun itself (confirmed by running it
# directly, outside hunternexus): it crashes with this exact
# AttributeError whenever the target's baseline request doesn't return
# HTTP 200 -- which is exactly what happens against any WAF/gateway-fronted
# host that blanket-denies unauthenticated requests (confirmed live against
# several Akamai-fronted hosts during an authorized engagement, all
# returning 403). Not fixable from hunternexus's side; this only makes
# the resulting log line readable instead of a truncated, confusing
# partial stack trace.
_ARJUN_KNOWN_CRASH_SIGNATURE = "'dict' object has no attribute 'status_code'"


def _describe_arjun_failure(stderr: str) -> str:
    if _ARJUN_KNOWN_CRASH_SIGNATURE in stderr:
        return (
            "arjun crashed internally (known upstream bug: it errors on any non-200 "
            "baseline response, e.g. a WAF/gateway returning 403 -- see github.com/s0md3v/Arjun). "
            "Not a hunternexus issue; x8 still ran independently against this URL."
        )
    if "Traceback (most recent call last)" in stderr:
        return f"arjun crashed internally (unrecognized traceback): {stderr.strip().splitlines()[-1][:200]}"
    return stderr.strip()[:300]


def x8_discover(config: Config, url: str, wordlist: Path | None = None, *, timeout: int = 600) -> list[str]:
    path = config.tool_path("x8")
    if not path:
        logger.warning("x8 not found on PATH -- download a release binary from github.com/Sh1Yo/x8")
        return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        out_path = Path(tmp.name)

    argv = [path, "-u", url, "-o", str(out_path), "-O", "json"]
    stdin_text = None
    if wordlist:
        argv += ["-w", str(wordlist)]
    else:
        # x8's -w reads from stdin when no file is given -- but with no
        # wordlist at all x8 falls back to its own built-in default list
        # when -w is omitted entirely, so just omit it rather than
        # pass an empty stdin that would short-circuit with zero params.
        pass

    result = run(argv, stdin_text=stdin_text, timeout=timeout)
    params: list[str] = []
    if out_path.is_file() and out_path.stat().st_size > 0:
        try:
            data = json.loads(out_path.read_text())
            # x8's real JSON shape (verified directly): a list of
            # {"found_params": [{"name": "...", ...}, ...], ...} per
            # url:method combination tested -- NOT a flat "parameters"
            # list of strings.
            if isinstance(data, list):
                for entry in data:
                    for p in entry.get("found_params", []):
                        name = p.get("name") if isinstance(p, dict) else None
                        if name:
                            params.append(name)
        except json.JSONDecodeError:
            logger.warning("x8 produced unparseable JSON output")
        out_path.unlink(missing_ok=True)
    elif not result.ok:
        logger.warning("x8 exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return dedupe_strings(params)


def discover_both(config: Config, url: str, *, timeout: int = 600) -> dict[str, list[str]]:
    """Runs both tools and returns per-tool results (not pre-merged) so
    the pipeline's dedupe step can track which technique found which
    parameter -- same source-attribution pattern used everywhere else."""
    return {
        "arjun": arjun_discover(config, url, timeout=timeout),
        "x8": x8_discover(config, url, timeout=timeout),
    }
