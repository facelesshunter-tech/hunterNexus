# Architecture

## Why an orchestrator, not a reimplementation

Subfinder, Amass, httpx, and puredns are already best-in-class at what
they do. Reimplementing subdomain enumeration, DNS resolution, or HTTP
probing from scratch would mean maintaining a permanently inferior
version of tools that are already actively developed and battle-tested.
hunterNexus instead follows the same pattern as other reference recon
frameworks: orchestrate specialized binaries rather than reimplement
them.

- **`utils/subprocess_runner.py`** is the one place external binaries get
  shelled out to, with consistent timeout and error handling.
- **`utils/http.py`** is the one place API-based sources get called, with
  a consistent User-Agent and timeout policy.
- **Every `modules/*.py` file is a thin, single-responsibility wrapper**
  around either an external tool or an external API (see
  `docs/MODULE-MAP.md` for the full list).

Things that are genuinely just DNS/HTTP protocol work with no advantage
to shelling out (PTR lookups, DMARC TXT record parsing, CSP header
parsing, certificate SAN extraction) are implemented natively in Python
instead of wrapping a CLI tool for them.

## Data flow

```
target domain
     │
     ▼
subdomain_passive.py ──┐
github_recon.py ───────┼──► dedupe.py ──► state.py (AssetStore, SQLite)
subdomain_bruteforce.py┤         │
permutation.py ─────────┘        │ (new assets this run vs. all-time)
                                  ▼
                         live_validation.py (httpx)
                                  │
                    ┌─────────────┼─────────────┐
                    ▼             ▼              ▼
          favicon_fingerprint  screenshotting   (tech already
                .py               .py            detected by httpx)
                    │             │
                    └──────┬──────┘
                           ▼
                scoring/prioritize.py (risk_score, risk_reasons)
                           │
                           ▼
                reporting/export.py (JSON + Markdown)
```

Everything upstream of `live_validation.py` produces a flat set of
candidate hostnames; `live_validation.py` is the single point where
liveness actually gets confirmed, and every stage after it operates only
on hosts known to be real and reachable.

## Why `state.py` exists (not just flat files)

Two capabilities depend on persistent, queryable state rather than a
one-shot script:

1. **Change detection** (`pipeline.py: change_report`) — "what's new
   since last time" requires remembering what was seen before. Recon
   against an active target is an ongoing process, not a single run, and
   a tool that can't answer that question forces a human to do the diff
   by hand.
2. **Source-reliability scorecard** (`pipeline.py: source_reliability`) —
   tracking which technique found which asset, across every scan, not
   just the current run, so effort can be redirected toward whichever
   sources are actually producing results for a given target.

SQLite was chosen over a flat JSON/CSV asset list specifically so these
two queries (`new_since`, grouped source counts) are cheap and don't
require re-reading or re-parsing the entire history on every run.

## What's deliberately not auto-recursive

A newly-found apex domain (via acquisitions, GitHub, or AI-assisted
pattern guessing) could in principle trigger re-running earlier stages
against it automatically. `pipeline.py` deliberately does not do this:
scope creep in authorized security testing has real consequences —
testing an asset you weren't authorized to touch is not a trivial
mistake. Expanding to a newly-discovered apex domain is left as an
explicit `hunternexus scan <new-domain>` call a human decides to make,
never something the tool does on its own.
