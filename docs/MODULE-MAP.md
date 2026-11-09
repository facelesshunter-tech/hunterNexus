# Module Reference

Every technique hunterNexus implements, where it lives, and its current
verification status. Nothing here is silently assumed to work — every
external tool integration was checked against real output before being
trusted, and every known limitation is called out explicitly rather than
hidden.

Status legend:
- ✅ **Implemented** — working code, calls a real API or external tool,
  verified against live output
- ⚠️ **Partial** — implemented with a specific, documented caveat (a
  best-effort API shape, a substituted data source, or a limitation in
  the underlying tool) — see the module's own docstring for the exact
  reasoning
- 📄 **Documented, not automated** — a real technique that is a GUI-only
  tool, a manual judgment call, or something whose automation would
  violate a service's terms of use; a reference doc covers the manual
  version instead

## Discovery and enumeration

| Technique | Module(s) | Status |
|---|---|---|
| ASN/IP-range discovery | `modules/asn_discovery.py` | ✅ via bgpview.io + RIPEstat (see module docstring for why not bgp.he.net directly) |
| Microsoft tenant / Autodiscover interrogation | `modules/msft_tenant.py` | ⚠️ the classic `GetFederationInformation`-based approach is dead; re-implemented via the still-functioning public OpenID/GetUserRealm endpoints — full tenant-domain enumeration needs an authenticated Graph query (documented in-module) |
| ASN→certificate scanning | `modules/cert_pivot.py: scan_cidrs` | ✅ |
| Cloud-provider IP ranges / certificate-transparency pivoting | `modules/asn_discovery.py: cloud_provider_ranges`, `modules/cert_pivot.py: kaeferjaeger_lookup` | ✅ |
| Reverse WHOIS | `modules/reverse_whois.py` | ✅ |
| Reverse DNS + shared-nameserver pivot | `modules/reverse_dns.py` | ✅ |
| Reverse IP (host.io) | `modules/reverse_ip.py` | ✅ |
| DMARC-sharing analysis | `modules/dmarc_pivot.py` | ⚠️ shared-identifier grouping across known subdomains is pure-DNS and fully implemented; reverse-searching the whole internet by identifier is best-effort via SecurityTrails |
| Acquisitions / subsidiary discovery | `modules/acquisitions.py` | ⚠️ SEC-API.io implemented directly; Crunchbase needs an enterprise agreement, not a self-serve key; Tracxn/Pitchbook/OCCRP Aleph documented as manual (`manual_research_checklist()` gives direct search URLs) |
| AI-assisted subdomain-pattern guessing and acquisition cross-referencing | `modules/ai_recon.py` | ✅ every suggestion carries a hard `verified: False` field — model output is never trusted blindly |
| CSP mining, crossdomain.xml, archived-URL mining | `modules/csp_misc.py` | ✅ |
| Passive subdomain enumeration (Subfinder, Amass, BBOT, assetfinder, crt.sh) | `modules/subdomain_passive.py` | ✅ |
| Google dork subdomain exclusion | `modules/subdomain_passive.py: google_exclusion_dork` | 📄 generates the query string only — mass-querying Google programmatically violates its terms of service |
| Subdomain-finder API aggregation | `modules/subdomain_passive.py: c99_subdomainfinder` | ✅ |
| GitHub secret/subdomain hunting (code search, dorking, TruffleHog) | `modules/github_recon.py` | ✅ |
| GitHub dorking (maintained dork database + real search execution) | `modules/github_recon.py: gitdorker_scan` | ✅ |
| Subdomain bruteforce (puredns/massdns, resolvers) | `modules/subdomain_bruteforce.py` | ✅ output is validated against a hostname-shape check before being trusted as a real discovery — puredns prints its own fatal errors to stdout, and without validation that text can otherwise be silently recorded as a false result |
| Permutation/alteration scanning | `modules/permutation.py` | ✅ |
| VHost scanning | `modules/vhost_scan.py` | ✅ |
| DNS intelligence / bulk resolution + wildcard filtering | `modules/dns_intel.py` | ✅ |
| Internet-wide asset intelligence (Uncover, Censys, urlscan.io) | `modules/internet_intel.py` | ✅ |
| Open/misconfigured cloud storage discovery (indexed search + active bucket brute-force) | `modules/open_storage.py` | ✅ |

## Live-host triage and enrichment

| Technique | Module(s) | Status |
|---|---|---|
| Live validation + tech-stack fingerprinting | `modules/live_validation.py` | ✅ |
| TLS/certificate probing (misconfiguration detection) | `modules/tls_probe.py` | ✅ |
| WAF fingerprinting | `modules/waf_detect.py` | ✅ capped host list + per-request timeout, so one unreachable host can't silently zero out results for the whole batch |
| Favicon-hash fingerprinting | `modules/favicon_fingerprint.py` | ✅ native hashing; fingerprint database must be user-supplied (see module docstring for why no hashes are hardcoded) |
| Screenshotting | `modules/live_validation.py`, `modules/screenshotting.py` | ✅ `gowitness` (native, no Docker needed) is the default engine and feeds structured title/screenshot-path data back into the report; `EyeWitness` is available separately for its default-credential checker |

## Content, endpoint, and parameter discovery

| Technique | Module(s) | Status |
|---|---|---|
| Directory/file content discovery | `modules/content_discovery.py` | ✅ auto-calibrated (ffuf `-ac`) so hosts that return one status for every path don't flood results with false positives |
| JS-aware crawling + historical URL mining | `modules/web_crawl.py` | ✅ |
| JS endpoint extraction, secret discovery, source-map recovery | `modules/js_analysis.py` | ✅ / ⚠️ source-map recovery is implemented natively rather than wrapping a third-party tool — see module docstring |
| Hidden parameter discovery | `modules/parameter_discovery.py` | ✅ runs two independent tools (different detection techniques) together deliberately, since neither alone finds everything the other does |
| API route brute-forcing | `modules/api_discovery.py` | ✅ uses a locally-compiled wordlist by default, with no dependency on a third-party hosted service; the per-route hit-record parser is confirmed against a real positive match |

## Scoring, verification, and reporting

| Technique | Module(s) | Status |
|---|---|---|
| Risk-based asset prioritization | `scoring/prioritize.py` | ✅ rule-based scoring for login pages, default content, redirects, Basic Auth, outdated frameworks, and a literal CVE-watchlist lookup table for edge-device products |
| EPSS + CISA KEV live scoring enrichment | `scoring/prioritize.py: refresh_cve_intel` | ✅ KEV catalog cached locally with a 24h freshness window, falling back to a stale cache rather than going dark if the feed is unreachable |
| Scoped CVE-watchlist verification | `modules/vuln_verify.py` | ✅ restricted to the exact CVE IDs the scoring layer already flagged — never a general scan |
| Reporting (ranked worklist) | `reporting/export.py` | ✅ JSON + Markdown |
| Architecture / tech-detection report | `reporting/architecture.py` | ✅ per-host TLS, WAF, and DNS data, kept in a separate file from the ranked worklist |
| Report template | `templates/VULNERABILITY_REPORT_TEMPLATE.md` | ✅ |
| Program/scope selection guidance | `docs/PROGRAM_SELECTION.md` | 📄 human judgment call, not automatable |

## Architectural capabilities (not single files)

- **Persistent state and change detection** — `pipeline.py`, `state.py`.
  Every asset ever seen is stored, so a later run can report what's new
  since the last one.
- **Source-reliability scorecard** — `state.py: source_reliability`.
  Tracks which technique found which asset, across every scan, with full
  per-tool attribution (not just a single generic category per asset).
- **Staged, senior-methodology pipeline** — `pipeline.py`. Passive
  discovery before active, cheap before expensive, with every stage
  degrading gracefully rather than failing the whole run when one tool
  or API is unavailable.
