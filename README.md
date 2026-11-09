# hunterNexus

A staged, senior-methodology reconnaissance orchestrator for authorized
security testing and bug bounty engagements.

hunterNexus coordinates best-in-class open-source recon tooling —
subdomain enumeration, DNS and TLS validation, live-host triage, content
and endpoint discovery, JavaScript analysis, parameter and API discovery,
and scoped vulnerability verification — into a single pipeline with
automatic cross-tool deduplication, persistent state for change
detection, and clean, separated reporting. It is built around one
operating principle: run the right tool at the right time, passive
before active, cheap before expensive, and never let one failing stage
silently degrade the rest of a scan.

## Why this exists

Most recon tooling either reimplements subdomain enumeration on its own
and stops there, or scopes itself to a single technique. hunterNexus
takes the opposite approach: it orchestrates proven, purpose-built tools
(Subfinder, Amass, httpx, dnsx, tlsx, puredns, dnsgen, ffuf, Katana,
Kiterunner, and others) rather than reimplementing them, and fills the
remaining gaps with direct, natively-implemented API and protocol logic
where no off-the-shelf tool exists — reverse WHOIS/DNS/IP pivoting,
DMARC-sharing discovery, favicon fingerprinting, GitHub dork generation,
and CVE-aware risk scoring. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the full design rationale.

Every external tool integration in this project was verified directly
against real output before being trusted — flag behavior, JSON schemas,
and edge-case failure modes were confirmed by running the tool, not
assumed from documentation. Where a limitation or caveat exists, it is
documented in the relevant module rather than hidden.

## What it does

- **Subdomain discovery** — passive (Subfinder, Amass, BBOT, assetfinder,
  crt.sh), active bruteforce (puredns), and permutation/alteration
  scanning (dnsgen), all deduplicated with full source attribution.
- **DNS and TLS validation** — bulk resolution and wildcard filtering
  (dnsx), certificate and TLS misconfiguration probing (tlsx), before any
  host is handed to a heavier stage.
- **Live-host triage** — tech-stack fingerprinting, favicon matching, WAF
  detection, and structured screenshotting.
- **Content and endpoint discovery** — directory/file fuzzing (ffuf, with
  automatic response calibration), JS-aware crawling and historical URL
  mining (Katana, gau).
- **JavaScript analysis** — endpoint extraction, secret discovery, and
  source-map recovery.
- **Hidden parameter and API discovery** — Arjun and x8 run together for
  parameter discovery; Kiterunner for API route brute-forcing, using a
  locally-compiled wordlist with no dependency on a third-party hosted
  service.
- **GitHub and cloud exposure** — code-search dorking and open
  cloud-storage bucket enumeration.
- **Internet-wide asset intelligence** — Shodan/Censys/FOFA aggregation
  and urlscan.io historical lookups.
- **Risk-aware scoring** — a rule-based prioritization layer (login
  pages, default content, exposed admin panels, outdated frameworks,
  SSL VPN/edge-device CVE matches) enriched with live EPSS and CISA KEV
  data, plus strictly scoped vulnerability verification — never a general
  scanner, only confirming the exact CVEs the scoring layer already
  flagged.
- **Persistent state and change detection** — every asset ever seen is
  stored, so a later run reports what's new since the last one, and a
  source-reliability scorecard shows which technique is actually earning
  its keep.

## Quickstart

```bash
pip install -e .
cp config/config.example.yaml config/config.yaml   # fill in whatever API keys you have
hunternexus config-check                             # see what's currently active
hunternexus run                                       # guided, interactive scan
```

`hunternexus run` is the guided entry point: it prompts for a target (or
a file of targets), confirms authorization, asks for a scan depth, and
runs the pipeline with live stage-by-stage progress. For scripting and
automation, `hunternexus scan <target> [flags...]` runs the same
pipeline non-interactively — see [`docs/SETUP.md`](docs/SETUP.md) for
the full flag reference and a staged usage walkthrough.

Full setup — every external tool's install command and every API key's
signup link — is in [`docs/SETUP.md`](docs/SETUP.md).

## What a scan produces

Every scan produces three separate, purpose-built output files, kept
deliberately distinct: what to look at first, what the infrastructure
actually looks like, and the raw output of any deep-dive tooling that
ran.

```
hunternexus-output/
├── assets.db                        # persistent SQLite asset inventory (full history)
├── example.com.json                 # this run's new assets + ranked live hosts
├── example.com.md                   # same, human-readable
├── example.com-architecture.md      # per-host tech stack, TLS/cert, WAF, DNS
├── example.com-findings.json        # raw output from any opt-in deep-dive stage
│                                     # (content discovery, crawling, JS analysis,
│                                     #  parameter/API discovery, scoped verification)
└── screenshots/example.com/         # if --screenshots was passed
```

```bash
hunternexus changes example.com --since-hours 168    # what's new this week
hunternexus sources --target example.com              # which technique found what
```

See [`docs/SETUP.md`](docs/SETUP.md) for a full step-by-step walkthrough,
including a staged, senior-methodology example of running the deep-dive
stages in the right order.

## Project layout

```
hunternexus/
  cli.py             # entrypoint: run / scan / changes / sources / config-check
  wizard.py           # interactive pre-flight prompts for `run`
  ui.py               # live stage-progress display for `run`
  banner.py           # startup banner
  pipeline.py         # orchestrates every module into one staged pipeline
  config.py           # API key + tool-path resolution (config.yaml + env vars)
  state.py            # SQLite asset inventory, new-asset / source-reliability queries
  models.py           # shared Asset / LiveHost data model
  modules/            # one file per technique — see docs/MODULE-MAP.md
  scoring/            # risk-based asset prioritization, EPSS/CISA-KEV enrichment
  reporting/          # export.py (ranked worklist), architecture.py (infra/tech map)
docs/
  MODULE-MAP.md       # every module, what it does, and its verification status
  ARCHITECTURE.md      # design rationale
  SETUP.md             # tool install guide + staged usage walkthrough
  PROGRAM_SELECTION.md # scope/engagement guidance
templates/
  VULNERABILITY_REPORT_TEMPLATE.md
config/
  config.example.yaml  # every supported API key and tool path, scaffolded
```

## Scope and responsible use

hunterNexus is built for authorized security testing only — bug bounty
programs you're enrolled in, or infrastructure you own or have explicit
written permission to test. Several stages (bruteforce, permutation,
content discovery, port scanning) actively generate traffic against
discovered hosts; confirm scope and the program's rules of engagement
before pointing any of them at a target. See
[`docs/PROGRAM_SELECTION.md`](docs/PROGRAM_SELECTION.md).

## Author

Built and maintained by **Emmanuel Uwa** (Faceless Hunter).

[LinkedIn](https://www.linkedin.com/in/emmanuel-uwa-091992195) · [GitHub](https://github.com/facelesshunter-tech)
