"""Screenshotting for recon triage.

No single tool here is canonical -- screenshotting tool choice is
largely user preference, so this module supports all three:

- `go_stare` -- fast, lightweight, no browser install needed.
- `gowitness_scan` -- the default/recommended engine. Native binary (v3
  no longer requires Docker), returns structured per-host data (title,
  status, screenshot path) that the pipeline folds directly into the
  final report.
- `eyewitness` -- kept specifically for its default-credential-checker,
  a capability that remains otherwise unmatched among these tools,
  despite EyeWitness being the oldest tool in this list. Its official
  installer insists on `sudo apt-get`, which this project won't run
  non-interactively -- but in practice every system dependency it wants
  (Chromium, chromedriver, Xvfb, jq, cmake) is commonly already present,
  leaving only a couple of pure-Python pip packages to install by hand.
  See docs/SETUP.md for the exact no-sudo install path that was actually
  used.

Not wired into the automated `scan --screenshots` pipeline by design --
unlike go-stare/gowitness, EyeWitness is meaningfully slower and its real
value (default-cred checking) is best spent deliberately, against your
top-scored hosts from `scoring/prioritize.py` after a normal scan, not
blanket-run against every discovered host. Call `eyewitness()` directly
for that targeted second pass.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run

logger = logging.getLogger("hunternexus.screenshotting")


def go_stare(config: Config, hosts: list[str], output_dir: Path, *, timeout: int = 1800) -> Path:
    path = config.tool_path("go-stare")
    if not path:
        logger.warning("go-stare not found on PATH -- install from github.com/dwisiswant0/go-stare")
        return output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    run([path, "-o", str(output_dir)], stdin_text="\n".join(hosts), timeout=timeout)
    return output_dir


@dataclass
class GowitnessResult:
    url: str
    final_url: str = ""
    status_code: int | None = None
    title: str = ""
    screenshot_path: str = ""
    failed: bool = False
    fail_reason: str = ""


def gowitness_scan(
    config: Config,
    hosts: list[str],
    output_dir: Path,
    *,
    threads: int = 20,
    timeout: int = 1800,
    fullpage: bool = False,
) -> list[GowitnessResult]:
    """Native gowitness v3 scan (`gowitness scan file`) -- no Docker
    required. Takes hosts on stdin (`-f -`), writes screenshots under
    output_dir/screenshots and structured JSON-lines results to
    output_dir/gowitness.jsonl, which this function parses and returns.

    This is the module's primary, recommended screenshotting path. For
    users who specifically want the old Docker-based invocation (e.g. no
    local Chrome/Chromium available and unwilling to let gowitness
    auto-download one), see `gowitness_scan_docker` below.
    """
    path = config.tool_path("gowitness")
    if not path:
        logger.warning("gowitness not found on PATH -- install with: go install github.com/sensepost/gowitness@latest")
        return []

    output_dir.mkdir(parents=True, exist_ok=True)
    screenshot_dir = output_dir / "screenshots"
    jsonl_path = output_dir / "gowitness.jsonl"

    argv = [
        path,
        "scan",
        "file",
        "-f",
        "-",
        "-s",
        str(screenshot_dir),
        "-t",
        str(threads),
        "--write-jsonl",
        "--write-jsonl-file",
        str(jsonl_path),
        "--log-scan-errors",
        "--skip-html",  # hunternexus doesn't use the raw HTML field; omitting it keeps the JSONL file small
    ]
    if fullpage:
        argv.append("--screenshot-fullpage")

    result = run(argv, stdin_text="\n".join(hosts), timeout=timeout)
    if not result.ok and not jsonl_path.is_file():
        logger.warning("gowitness scan failed: %s", result.stderr.strip()[:500])
        return []

    results: list[GowitnessResult] = []
    if jsonl_path.is_file():
        for line in jsonl_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            screenshot_name = record.get("file_name", "")
            results.append(
                GowitnessResult(
                    url=record.get("url", ""),
                    final_url=record.get("final_url", record.get("url", "")),
                    status_code=record.get("response_code") or record.get("status_code"),
                    title=record.get("title", ""),
                    screenshot_path=str(screenshot_dir / screenshot_name) if screenshot_name else "",
                    failed=bool(record.get("failed", False)),
                    fail_reason=record.get("failed_reason", ""),
                )
            )
    return results


def gowitness_scan_docker(
    config: Config, httpx_output_file: Path, data_dir: Path, *, threads: int = 5, timeout: int = 1800
) -> None:
    """Fallback path using gowitness's original docker-based invocation,
    kept for environments with no local Chrome/Chromium and no desire to
    let gowitness auto-download one:
    `docker run --rm -v $(pwd):/data leonjza/gowitness gowitness file httpxOutput --threads 5`.

    Note this uses the OLDER gowitness v2 CLI syntax (`gowitness file`),
    which is what that published Docker image still runs -- gowitness_scan()
    above uses the current v3 syntax (`gowitness scan file`) against a
    natively installed binary and is the recommended path when available."""
    docker_path = config.tool_path("docker")
    if not docker_path:
        logger.warning("docker not found on PATH -- gowitness-via-docker skipped")
        return
    data_dir.mkdir(parents=True, exist_ok=True)
    argv = [
        docker_path,
        "run",
        "--rm",
        "-v",
        f"{data_dir}:/data",
        "leonjza/gowitness",
        "gowitness",
        "file",
        f"/data/{httpx_output_file.name}",
        "--threads",
        str(threads),
    ]
    result = run(argv, timeout=timeout)
    if not result.ok:
        logger.warning("gowitness docker run failed: %s", result.stderr.strip()[:300])


def eyewitness(config: Config, hosts_file: Path, output_dir: Path, *, timeout: int = 1800) -> Path:
    """Run EyeWitness specifically for its default-credential-checker --
    see this module's docstring for why it's not part of the automated
    `scan --screenshots` pipeline. Intended usage: after a normal scan,
    take the top N hosts from the risk-ranked report and run this
    against just those, not against every discovered host.

    Writes hosts_file's contents are NOT read by this function -- it's
    passed straight through to EyeWitness's own `-f` flag, so hosts_file
    must already exist on disk (one URL per line) before calling this.
    """
    path = config.tool_path("eyewitness") or config.tool_path("EyeWitness")
    if not path:
        logger.warning(
            "EyeWitness not found on PATH -- see docs/SETUP.md for the no-sudo "
            "install path (most of its deps are usually already present)"
        )
        return output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    argv = [path, "--web", "-f", str(hosts_file), "-d", str(output_dir), "--no-prompt"]
    result = run(argv, timeout=timeout)
    if not result.ok and not (output_dir / "report.html").is_file():
        logger.warning("EyeWitness run failed: %s", result.stderr.strip()[:300])
    return output_dir
