"""Safe wrapper for shelling out to the external recon binaries this
project relies on (subfinder, amass, httpx, puredns, dnsgen, naabu,
VHostScan, gowitness, github-subdomains, trufflehog, massdns, ...).

hunternexus deliberately does NOT reimplement what these tools already do
well -- Subfinder/Amass/httpx/puredns are best-in-class at what they do,
and reconftw/reNgine (both well-known reference frameworks) take the same
orchestrator-over-binaries approach. This module is the one place that
pattern is implemented, so every other module stays simple.
"""

from __future__ import annotations

import logging
import shlex
import subprocess
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("hunternexus.subprocess")


class ToolNotFoundError(RuntimeError):
    def __init__(self, tool: str, install_hint: str = ""):
        msg = f"required tool '{tool}' not found on PATH."
        if install_hint:
            msg += f" Install with: {install_hint}"
        super().__init__(msg)
        self.tool = tool


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(
    argv: list[str],
    *,
    stdin_text: Optional[str] = None,
    timeout: Optional[int] = 600,
    cwd: Optional[str] = None,
    check: bool = False,
) -> RunResult:
    """Run an external tool. Never raises on nonzero exit unless check=True --
    callers decide whether a given tool's nonzero exit is fatal (many recon
    tools exit nonzero on "no results found", which is not an error)."""

    logger.debug("running: %s", " ".join(shlex.quote(a) for a in argv))
    try:
        proc = subprocess.run(
            argv,
            input=stdin_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
    except FileNotFoundError as e:
        raise ToolNotFoundError(argv[0]) from e
    except subprocess.TimeoutExpired as e:
        # Python quirk, verified directly: TimeoutExpired.stdout/.stderr are
        # always raw bytes, even when text=True was passed to subprocess.run
        # -- unlike the normal successful-completion path, which decodes
        # properly. Decoding manually here avoids leaking `b'...'`-repr
        # bytes objects into every caller downstream (found while testing
        # katana_crawl() against a slow target).
        partial_stdout = e.stdout.decode("utf-8", errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        partial_stderr = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return RunResult(returncode=124, stdout=partial_stdout, stderr=f"timed out after {timeout}s: {partial_stderr}")

    result = RunResult(proc.returncode, proc.stdout, proc.stderr)
    if check and not result.ok:
        raise subprocess.CalledProcessError(proc.returncode, argv, proc.stdout, proc.stderr)
    return result


def run_pipeline(stages: list[list[str]], *, stdin_text: Optional[str] = None, timeout: int = 600) -> RunResult:
    """Chain several tools together the way a typical recon one-liner does,
    e.g. `cat subdomains.txt | dnsgen - | puredns resolve --resolvers resolvers.txt`.
    Each stage's stdout becomes the next stage's stdin."""
    data = stdin_text
    last = RunResult(0, "", "")
    for argv in stages:
        last = run(argv, stdin_text=data, timeout=timeout)
        data = last.stdout
    return last
