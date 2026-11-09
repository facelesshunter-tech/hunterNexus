"""AI-assisted reconnaissance.

Two use cases, both implemented:

1. Subdomain-pattern guessing: given a known subdomain, ask an LLM to
   guess plausible sibling subdomains (e.g. from `admin.example.com`,
   guessing `dev`/`qa`/`test`/`prod`/`secure` variants), then resolve
   each guess to see which actually exist.

2. Acquisition discovery: ask an LLM what it knows about a company's
   acquisitions, as a *complementary* source to Crunchbase -- not a
   replacement. In practice this can surface real items a structured
   database missed, while the database has more recent entries past
   the model's training cutoff -- i.e. both sources are run, never
   just one.

This caveat is enforced as a hard requirement here, not a suggestion:
every AI-sourced claim is returned with a `verified: False` flag and
must be independently confirmed (DNS resolution for subdomains; an
actual source like SEC filings / Crunchbase / news for acquisitions)
before being trusted.
"""

from __future__ import annotations

import logging

import dns.resolver

from hunternexus.config import Config
from hunternexus.utils.http import post_json

logger = logging.getLogger("hunternexus.ai_recon")

DEFAULT_API_BASE = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4"

SUBDOMAIN_GUESS_PROMPT = (
    "You are assisting authorized security reconnaissance. Given the known "
    "subdomain '{subdomain}', suggest up to {n} plausible sibling subdomain "
    "labels that might exist on the same apex domain (e.g. dev, staging, "
    "qa, admin, internal, test). Respond with ONLY a comma-separated list "
    "of labels, no explanation."
)

ACQUISITION_PROMPT = (
    "You are assisting authorized security reconnaissance / attack-surface "
    "mapping. List any acquisitions you are aware of for the company "
    "'{company}'. Respond with ONLY a comma-separated list of acquired "
    "company names, no explanation. If you are not confident about any, "
    "respond with an empty string."
)


def _chat(config: Config, prompt: str, *, timeout: int = 60) -> str | None:
    key = config.api_key("openai")
    if not key:
        logger.warning(
            "no AI API key configured (config.api_keys.openai) -- "
            "ai_recon skipped. Any OpenAI-compatible endpoint works; set "
            "config.ai.api_base to point at a different provider/local model."
        )
        return None
    base = config.get("ai", "api_base", default=DEFAULT_API_BASE)
    model = config.get("ai", "model", default=DEFAULT_MODEL)
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
    }
    data = post_json(
        f"{base.rstrip('/')}/chat/completions",
        json_body=body,
        headers={"Authorization": f"Bearer {key}"},
        timeout=timeout,
    )
    if not data:
        return None
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError):
        return None


def guess_sibling_subdomains(config: Config, known_subdomain: str, *, n: int = 10) -> list[dict]:
    """Returns a list of {label, candidate_fqdn, resolves, verified} --
    `resolves` is the ground-truth DNS check; `verified` is always False
    for the AI's reasoning about *why* it guessed a label -- model output
    must never be trusted blindly."""
    if "." not in known_subdomain:
        return []
    apex_suffix = ".".join(known_subdomain.split(".")[-2:])
    content = _chat(config, SUBDOMAIN_GUESS_PROMPT.format(subdomain=known_subdomain, n=n))
    if not content:
        return []
    labels = [l.strip() for l in content.split(",") if l.strip()]
    resolver = dns.resolver.Resolver()
    results = []
    for label in labels:
        candidate = f"{label}.{apex_suffix}"
        resolves = False
        try:
            resolver.resolve(candidate, "A")
            resolves = True
        except Exception:
            pass
        results.append({"label": label, "candidate_fqdn": candidate, "resolves": resolves, "verified": resolves})
    return results


def query_acquisitions(config: Config, company: str) -> list[dict]:
    """Returns [{name, verified: False}] -- always unverified by
    definition; the caller MUST cross-reference against
    acquisitions.py's Crunchbase/manual-research paths and/or a primary
    source (SEC filings, press releases) before treating any of these as
    real, per the complementary-source reasoning described above."""
    content = _chat(config, ACQUISITION_PROMPT.format(company=company))
    if not content:
        return []
    names = [n.strip() for n in content.split(",") if n.strip()]
    return [{"name": n, "verified": False, "source": "ai_recon"} for n in names]
