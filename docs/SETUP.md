# Setup

## 1. Python environment

Two ways to install, depending on how you want to run it:

**Option A — project-local venv** (if you're actively developing the
tool itself):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

The `hunternexus` command only works while that venv is activated.

**Option B — global command via pipx** (recommended for regular use —
run `hunternexus` from any directory, no activation needed):

```bash
pipx install -e /path/to/hunterNexus
```

`-e` (editable) means `pipx` links directly to your checkout rather than
copying it, so `git pull`-ing new changes takes effect immediately with
no reinstall. Confirm it worked:

```bash
hunternexus --help
```

If `hunternexus: command not found`, pipx's bin directory isn't on your
`PATH` yet — run `pipx ensurepath`, then open a new terminal.

## 2. External tool binaries

hunternexus orchestrates these rather than reimplementing them (see
`docs/ARCHITECTURE.md` for why). Install whichever ones you want — every
module degrades gracefully with a clear warning if its tool is missing,
so you don't need all of them to get started.

| Tool | Install | Used by |
|---|---|---|
| [subfinder](https://github.com/projectdiscovery/subfinder) | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | `subdomain_passive.py` |
| [amass](https://github.com/owasp-amass/amass) | `go install github.com/owasp-amass/amass/v4/...@master` | `subdomain_passive.py` |
| [bbot](https://github.com/blacklanternsecurity/bbot) | `pipx install bbot` | `subdomain_passive.py` (optional) |
| [puredns](https://github.com/d3mondev/puredns) | `go install github.com/d3mondev/puredns/v2@latest` (needs [massdns](https://github.com/blechschmidt/massdns) too) | `subdomain_bruteforce.py`, `permutation.py` |
| [dnsgen](https://github.com/ProjectAnte/dnsgen) | `pip install dnsgen` | `permutation.py` |
| [alterx](https://github.com/projectdiscovery/alterx) | `go install github.com/projectdiscovery/alterx/cmd/alterx@latest` | `permutation.py` (alternative engine) |
| [naabu](https://github.com/projectdiscovery/naabu) | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` | `port_scan.py` |
| [rustscan](https://github.com/RustScan/RustScan) | see repo | `port_scan.py` (optional) |
| [smap](https://github.com/s0md3v/Smap) | `go install github.com/s0md3v/smap/cmd/smap@latest` | `port_scan.py` (needs Shodan key) |
| [httpx](https://github.com/projectdiscovery/httpx) | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` — **not** the Python `httpx` pip package | `live_validation.py` |
| [go-stare](https://github.com/dwisiswant0/go-stare) | see repo | `screenshotting.py` |
| [gowitness](https://github.com/sensepost/gowitness) | `go install github.com/sensepost/gowitness@latest` (v3, native -- no Docker needed) | `screenshotting.py` (default `scan --screenshots` engine) |
| [EyeWitness](https://github.com/RedSiege/EyeWitness) | see §4 below -- usually no-sudo | `screenshotting.py` (optional, for default-cred-checker; not part of the automated pipeline) |
| [VHostScan](https://github.com/codingo/VHostScan) | `pip install VHostScan` | `vhost_scan.py` |
| [github-subdomains](https://github.com/gwen001/github-subdomains) | `go install github.com/gwen001/github-subdomains@latest` | `github_recon.py` |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | see repo | `github_recon.py` (optional) |
| [FavFreak](https://github.com/devanshbatham/FavFreak) | `git clone` it; point `tools.favfreak` at `favfreak.py` | `favicon_fingerprint.py` (optional — native hashing works without it) |
| [waymore](https://github.com/xnl-h4ck3r/waymore) | `pip install waymore` | `csp_misc.py` (optional) |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | `go install github.com/tomnomnom/assetfinder@latest` | `subdomain_passive.py` |
| [dnsx](https://github.com/projectdiscovery/dnsx) | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` | `dns_intel.py` |
| [tlsx](https://github.com/projectdiscovery/tlsx) | `go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest` | `tls_probe.py` |
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | `pip install wafw00f` | `waf_detect.py` |
| [uncover](https://github.com/projectdiscovery/uncover) | `go install github.com/projectdiscovery/uncover/cmd/uncover@latest` | `internet_intel.py` |
| [ffuf](https://github.com/ffuf/ffuf) | `go install github.com/ffuf/ffuf/v2@latest` | `content_discovery.py` (needs a wordlist -- [SecLists](https://github.com/danielmiessler/SecLists) at `~/tools/SecLists` is the default) |
| [katana](https://github.com/projectdiscovery/katana) | `go install github.com/projectdiscovery/katana/cmd/katana@latest` | `web_crawl.py` |
| [gau](https://github.com/lc/gau) | `go install github.com/lc/gau/v2/cmd/gau@latest` | `web_crawl.py` |
| [xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder) | `pip install xnLinkFinder` | `js_analysis.py` |
| [SecretFinder](https://github.com/m4ll0k/SecretFinder) | `git clone` it; point `tools.secretfinder` at `SecretFinder.py` | `js_analysis.py` |
| [GitDorker](https://github.com/obheda12/GitDorker) | `git clone` it; needs its `Dorks/` directory alongside | `github_recon.py: gitdorker_scan` (needs GitHub tokens) |
| [cloud_enum](https://github.com/initstring/cloud_enum) | `git clone` it; point `tools.cloud_enum` at `cloud_enum.py` | `open_storage.py: cloud_enum_scan` |
| [Arjun](https://github.com/s0md3v/Arjun) | `pip install arjun` | `parameter_discovery.py` |
| [x8](https://github.com/Sh1Yo/x8) | download a release binary | `parameter_discovery.py` |
| [Kiterunner](https://github.com/assetnote/kiterunner) | download a release binary (`kr`) -- no clean `go install` path | `api_discovery.py` (uses Assetnote's hosted wordlists by default) |
| [nuclei](https://github.com/projectdiscovery/nuclei) | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | `vuln_verify.py` -- used **only** for scoped CVE-watchlist verification, never general scanning |

Run `hunternexus config-check` any time to see exactly which of these
are currently detected on `PATH`.

## 3. API keys

Copy `config/config.example.yaml` to `config/config.yaml` and fill in
whatever you have.

**If you installed with pipx (Option B above)**, `hunternexus` runs from
any directory, so it won't find a `config/config.yaml` relative to
wherever your shell happens to be. Put your filled-in config at
`~/.config/hunternexus/config.yaml` instead — that's the default path it
checks when no local `config/config.yaml` is found in the current
directory:

```bash
mkdir -p ~/.config/hunternexus
cp config/config.example.yaml ~/.config/hunternexus/config.yaml
# edit ~/.config/hunternexus/config.yaml with your real keys
```

Recommended priority order for getting the most out of a fresh install:

1. **Chaos** — free, instant signup: https://chaos.projectdiscovery.io
2. **GitHub tokens** — free, instant: https://github.com/settings/tokens
   (classic tokens, no special scopes needed for code search). Get
   **several** — hunterNexus round-robins across all configured tokens.
3. **Shodan** — freemium: https://account.shodan.io/register
4. **Free/cheap**: FacebookCT (requires creating a Facebook Developer
   app — see `config/config.example.yaml`'s comments for the full
   walkthrough), c99/RiskIQ, dnsdumpster
5. **Paid/limited**: whoxy, whoisxmlapi, host.io, SecurityTrails,
   Crunchbase (enterprise sales contact, not self-serve), sec-api.io
   (free tier available), greyhatwarfare
6. **Censys** (search.censys.io -- Personal Access Token, format
   `API_ID:SECRET`) and **urlscan.io** (free tier) -- both optional,
   feed `internet_intel.py` alongside Uncover (which itself needs no
   dedicated key beyond whatever Shodan/Censys/etc. keys you already
   have configured for the underlying engines it queries)

## 4. Not wired up (or not automated) — and why (read this before filing an issue)

- **Tracxn, Pitchbook, OCCRP Aleph**: browse-only / enterprise-gated web
  tools with no public API suited to this use case.
  `acquisitions.py: manual_research_checklist()` gives you direct search
  URLs instead.
- **Google Alerts**: no public API for programmatically creating an
  alert. Set one up by hand for `"<company> acquisition"` instead.
- **Mass Google/Bing dorking**: search engines actively block scripted
  querying at volume. `subdomain_passive.py: google_exclusion_dork()`
  generates the query string for you to paste into a browser manually
  instead.
- **DuckDuckGo Tracker Radar / Cloudflare Radar**: both have real public
  APIs/datasets; not wired up because there's no concrete recon
  technique that needs them yet — candidates for a follow-on module if a
  specific use case comes up.
- **check_mdi.py-style Microsoft tenant interrogation**: Microsoft
  changed `GetFederationInformation`'s behavior, breaking the classic
  approach. Not reimplemented on purpose — see `msft_tenant.py` for the
  working replacement approach via the still-functioning public
  OpenID/GetUserRealm endpoints.
- **EyeWitness**: kept alongside `gowitness` specifically for its
  default-credential-checker, a capability `gowitness` doesn't have. Not
  part of the automated `scan --screenshots` pipeline by design (see
  `screenshotting.py`'s module docstring) -- call
  `screenshotting.eyewitness()` directly against a short list of your
  top-scored hosts after a normal scan, not against everything.

  Its official installer (`setup/setup.sh`) hard-requires root and
  refuses to run otherwise -- but in practice almost everything it wants
  (Chromium, chromedriver, Xvfb, jq, cmake) is commonly already present
  on a system that's done any security-tool work, leaving only a couple
  of pure-Python packages. The no-sudo path that actually worked:

  ```bash
  git clone https://github.com/RedSiege/EyeWitness.git ~/tools/EyeWitness
  # Check what's actually missing before assuming you need the root-only installer:
  which chromium chromedriver jq cmake Xvfb
  python3 -c "import selenium, netaddr, psutil"
  # Typically only this is missing:
  pip3 install --user pyvirtualdisplay
  pip3 install --user -r ~/tools/EyeWitness/setup/requirements.txt
  # Verify:
  python3 ~/tools/EyeWitness/Python/EyeWitness.py --web --single https://example.com -d /tmp/ew-test --no-prompt
  ```

  If your system genuinely lacks Chromium/chromedriver/Xvfb, you *will*
  need `sudo apt-get install chromium chromium-driver xvfb jq cmake` (or
  your distro's equivalents) for those specific packages -- there's no
  way around installing a browser without root. The point above is just
  that the official script assumes you need the *entire* list via root,
  when usually you don't.

  Point `tools.eyewitness` at a wrapper script (or the real binary) once
  installed; a one-line shim like
  `exec python3 "$HOME/tools/EyeWitness/Python/EyeWitness.py" "$@"`
  saved as `~/.local/bin/eyewitness` (executable) is the simplest way to
  get it discovered on `PATH` alongside everything else.

## 5. First run

```bash
hunternexus config-check
hunternexus run
```

`hunternexus run` is the guided entry point -- it prompts for your
target (or a file of targets), an explicit authorization confirmation,
and a scan depth (Quick / Standard / Full / Advanced), then runs with
live stage-by-stage progress. This is the easiest way to run a scan,
and the one worth using for anything presented to someone else.

For scripting and automation, the same pipeline is available
non-interactively via flags:

```bash
hunternexus scan example.com
hunternexus scan example.com --github --screenshots --favicon --favicon-db ./favfreak-hashes.json
hunternexus scan example.com --bruteforce --permutation --wordlist words.txt --resolvers resolvers.txt
hunternexus changes example.com --since-hours 168
hunternexus sources --target example.com
```

Only scan targets you are authorized to test.

## 6. A senior-methodology deep-dive run, step by step

Everything in step 5 covers the cheap, passive-by-default stages
(`--subfinder`/`--amass`/`--crtsh`/`--assetfinder`, DNS validation, live
validation, TLS probing -- all on by default). The deep-dive stages below
are deliberately opt-in, because they're either active/intrusive, slow,
or both -- turn them on one at a time, in roughly this order, the same
way a senior hunter would stage their own manual workflow:

```bash
# 1. Widen passive discovery as far as it goes (GitHub + GitDorker +
#    cloud_enum + Uncover), still zero traffic to the target itself:
hunternexus scan example.com --github --gitdorker --gitdorker-keyword example \
  --cloud-enum --cloud-enum-keyword example --uncover --uncover-query 'hostname:"example.com"'

# 2. Confirm you actually want to generate live traffic, then fingerprint
#    what's really there (WAF + screenshots + favicon):
hunternexus scan example.com --waf-detect --screenshots --favicon --favicon-db ./favfreak-hashes.json

# 3. Crawl what's live and mine what used to be live (feeds JS analysis):
hunternexus scan example.com --web-crawl --js-analysis

# 4. Now that you have real endpoints (from step 3), look for hidden
#    parameters and undocumented API routes on the ones worth your time:
hunternexus scan example.com --parameter-discovery --api-discovery

# 5. Only once scoring has flagged a host against the edge-device CVE
#    watchlist, confirm it with a SCOPED nuclei run (never general
#    scanning) and sharpen the score with live EPSS/KEV data:
hunternexus scan example.com --vuln-verify --cve-intel
```

Every run produces three separate, "well arranged and neat" output
files per target (see the README's "What a scan produces" section) --
the ranked worklist, the architecture/tech-detection map, and (if any
deep-dive stage was enabled) the raw auxiliary findings file. Nothing
from the deep-dive stages gets silently merged into the ranked
worklist; it's kept in its own file precisely so you can tell "what
should I look at first" apart from "what did every tool actually find."
