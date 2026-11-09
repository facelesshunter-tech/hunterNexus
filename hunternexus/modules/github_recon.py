"""GitHub enumeration.

Most GitHub recon tooling is built to scan a *single repo or org*, which
is the opposite of what matters here -- the goal is to scour all of
GitHub (especially personal repos) for subdomains, secrets, and
tech-stack signals tied to a target. This module implements three
complementary techniques:

1. `github_subdomains` -- wraps the github-subdomains tool
   (`github-subdomains -d <domain> -t <token>`). This needs *many tokens
   and many runs* to be effective, since GitHub code search is both
   rate-limited and non-exhaustive per query.

2. `dork_urls` -- builds a curated list of GitHub code-search dork URLs,
   one per sensitive-file/keyword pattern, for a given target term.

3. `trufflehog_scan` -- hands a discovered repo/org off to TruffleHog for
   secret scanning, completing an "apexes > github-subdomains >
   Trufflehog" pipeline.
"""

from __future__ import annotations

import csv
import itertools
import logging
import tempfile
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run
from hunternexus.utils.dedupe import dedupe_strings

logger = logging.getLogger("hunternexus.github_recon")

# Dork keyword list targeting common secret-file and credential patterns
# surfaced by GitHub code search (keys, tokens, config files, etc.).
DORK_TERMS = [
    "password",
    "npmrc _auth",
    "dockercfg",
    "pem private",
    "extension:pem private",
    "id_rsa",
    "aws_access_key_id",
    "s3cfg",
    "htpasswd",
    "git-credentials",
    "bashrc password",
    "sshd_config",
    "xoxp OR xoxb OR xoxa",
    "SECRET_KEY",
    "client_secret",
    "github_token",
    "api_key",
    "FTP",
    "app_secret",
    "passwd",
    ".env",
    ".exs",
    "beanstalkd.yml",
    "deploy.rake",
]


class TokenPool:
    """Round-robins across multiple GitHub tokens. GitHub code search
    needs many API keys and many runs to be exhaustive, since each
    token is rate-limited independently."""

    def __init__(self, tokens: list[str]):
        if not tokens:
            raise ValueError("TokenPool requires at least one token")
        self._cycle = itertools.cycle(tokens)

    def next(self) -> str:
        return next(self._cycle)


def github_subdomains(config: Config, domain: str, *, timeout: int = 300) -> list[str]:
    path = config.tool_path("github-subdomains")
    tokens = config.api_keys_list("github")
    if not path:
        logger.warning("github-subdomains not found on PATH -- install from github.com/gwen001/github-subdomains")
        return []
    if not tokens:
        logger.warning(
            "no GitHub tokens configured (config.api_keys.github, a list) -- "
            "github-subdomains skipped. A *pool* of tokens is strongly "
            "recommended here, not just one, since GitHub's rate limit is per-token."
        )
        return []
    pool = TokenPool(tokens)
    argv = [path, "-d", domain, "-t", pool.next()]
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("github-subdomains exited %s: %s", result.returncode, result.stderr.strip()[:300])
    # Output mixes bare hostnames and github.com/... URLs that merely
    # mention the target string; keep only lines that look like a hostname
    # of the target domain -- the same filtering judgment applied when
    # eyeballing raw results by hand.
    hits = [line.strip() for line in result.stdout.splitlines() if domain in line and "github.com" not in line]
    return dedupe_strings(hits)


def dork_urls(target_term: str) -> dict[str, str]:
    """Generates GitHub code-search dork URLs for a given target term
    (usually the apex domain)."""
    urls: dict[str, str] = {}
    for term in DORK_TERMS:
        query = f'"{target_term}"+{term}'
        encoded = urllib.parse.quote(query)
        urls[term] = f"https://github.com/search?q={encoded}&type=Code"
    return urls


@dataclass
class GitDorkHit:
    user: str
    dork: str
    keyword: str
    url: str
    result_count: str


def gitdorker_scan(
    config: Config,
    keyword: str,
    *,
    dorks_file: str | None = None,
    threads: int = 3,
    timeout: int = 1800,
) -> list[GitDorkHit]:
    """GitDorker -- a more full-featured alternative/supplement to this
    module's own built-in dork_urls() generator, with its own maintained
    dork database and actual GitHub code-search API execution (dork_urls()
    only generates browser-paste URLs, it doesn't execute searches itself).
    Real output naming convention and CSV columns verified directly: the
    tool appends `_gh_dorks.csv` to whatever `-o` prefix is given, and the
    keyword-search CSV header is exactly
    ['USER', 'DORK', 'KEYWORD', 'URL', 'NUMBER OF RESULTS']."""
    path = config.tool_path("gitdorker") or config.tool_path("GitDorker")
    if not path:
        logger.warning("gitdorker not found on PATH -- install from github.com/obheda12/GitDorker")
        return []

    tokens = config.api_keys_list("github")
    if not tokens:
        logger.warning("no GitHub tokens configured (config.api_keys.github) -- gitdorker_scan skipped")
        return []

    dorks_file = dorks_file or str(
        Path.home() / "tools" / "GitDorker" / "Dorks" / "medium_dorks.txt"
    )
    if not Path(dorks_file).is_file():
        logger.warning("dorks file not found at %s -- pass dorks_file explicitly", dorks_file)
        return []

    with tempfile.TemporaryDirectory() as tmpdir:
        out_prefix = str(Path(tmpdir) / "scan")
        pool = TokenPool(tokens)
        argv = [path, "-d", dorks_file, "-k", keyword, "-t", pool.next(), "-o", out_prefix, "-e", str(threads)]
        result = run(argv, timeout=timeout)

        csv_path = Path(f"{out_prefix}_gh_dorks.csv")
        hits: list[GitDorkHit] = []
        if csv_path.is_file() and csv_path.stat().st_size > 0:
            with open(csv_path, newline="") as f:
                reader = csv.DictReader(f, fieldnames=["USER", "DORK", "KEYWORD", "URL", "NUMBER OF RESULTS"])
                for row in reader:
                    hits.append(
                        GitDorkHit(
                            user=row.get("USER", ""),
                            dork=row.get("DORK", ""),
                            keyword=row.get("KEYWORD", ""),
                            url=row.get("URL", ""),
                            result_count=row.get("NUMBER OF RESULTS", ""),
                        )
                    )
        elif not result.ok:
            logger.warning("gitdorker exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return hits


def trufflehog_scan(config: Config, repo_or_org_url: str, *, timeout: int = 1800) -> str:
    """The 'Apexes > github-subdomains > Trufflehog' pipeline's final
    stage: secret-scan a specific repo once github-subdomains/dorking has
    surfaced it as relevant. Returns raw TruffleHog JSON-lines output for
    the caller to parse/store."""
    path = config.tool_path("trufflehog")
    if not path:
        logger.warning("trufflehog not found on PATH -- install from github.com/trufflesecurity/trufflehog")
        return ""
    argv = [path, "github", "--repo", repo_or_org_url, "--json"]
    result = run(argv, timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("trufflehog exited %s: %s", result.returncode, result.stderr.strip()[:300])
    return result.stdout
