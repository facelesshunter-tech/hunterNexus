"""The orchestrator that ties every module together into a single,
"feed results forward" pipeline:
discovery -> dedupe -> DNS validation -> liveness/tech-detect -> TLS/WAF
enrichment -> screenshot/fingerprint -> deep-dive (content discovery,
crawling, JS analysis, parameter/API discovery) -> scoped vuln
verification -> score -> report, with every asset ever seen persisted so
later runs can report what's new (a "recon is a cycle" /
continuous-monitoring approach).

Staging discipline, applied deliberately: cheap/passive/safe stages
default ON, active/intrusive/slow stages default OFF and must be opted
into explicitly. Dedupe runs twice (after passive discovery, and again
after active bruteforce/permutation) so nothing downstream -- DNS
resolution, httpx, tlsx, wafw00f, ffuf, katana, Kiterunner -- ever
wastes a pass on a candidate it's already processed under a different
name. A DNS resolution pass (dnsx) sits between "candidate name" and
"worth probing with httpx," dropping anything that doesn't actually
resolve before any heavier stage spends time on it -- the same "don't
waste a stage on dead hosts" discipline dns_intel.py's own docstring
describes.

This is intentionally a straight-line pipeline, not an unbounded
auto-recursive one: the "recon is a cycle" idea (new apex domains found
via acquisitions/GitHub/AI should trigger re-running earlier stages
against them) is realized here as "run hunternexus again with the new
apex domain as the target," using the AssetStore's new-asset tracking
to tell you when that's worth doing -- not as automatic unbounded
recursion within a single run, which would have no natural stopping
point and could silently balloon scope far beyond what was authorized
for a given target.

Three separate output files per run, deliberately not merged into one
blob (a "well arranged and neat" note-taking philosophy, reproduced
structurally):
  - `<target>.json` / `<target>.md`     -- the ranked worklist (export.py)
  - `<target>-architecture.md`          -- the infra/tech-detection map
                                            (reporting/architecture.py)
  - `<target>-findings.json`            -- raw auxiliary results from the
                                            opt-in deep-dive tools (GitDorker,
                                            cloud_enum, ffuf, katana/gau,
                                            xnLinkFinder/SecretFinder/source
                                            maps, Arjun/x8, Kiterunner,
                                            scoped nuclei verification)

`Pipeline.run()` accepts an optional `on_stage` callback
(label: str, status: "start" | "done", detail: str) -> None, invoked
around every meaningful unit of work. This is how a caller (the `scan`
CLI command, the `run` interactive wizard, or any future caller) can
show live progress without duplicating the orchestration logic above --
the callback is purely an observer, it has no influence on control flow.
It is optional and defaults to a no-op, so passing nothing keeps the
pipeline's behavior identical to not having this hook at all.
"""

from __future__ import annotations

import json
import logging
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from hunternexus.config import Config
from hunternexus.models import Asset, AssetType, LiveHost, Source
from hunternexus.state import AssetStore
from hunternexus.utils.dedupe import dedupe_assets, dedupe_strings
from hunternexus.utils.http import strip_scheme
from hunternexus.modules import (
    subdomain_passive,
    subdomain_bruteforce,
    permutation,
    github_recon,
    open_storage,
    internet_intel,
    dns_intel,
    live_validation,
    tls_probe,
    waf_detect,
    screenshotting,
    favicon_fingerprint,
    content_discovery,
    web_crawl,
    js_analysis,
    parameter_discovery,
    api_discovery,
    vuln_verify,
)
from hunternexus.scoring import prioritize
from hunternexus.scoring.prioritize import rank
from hunternexus.reporting import export, architecture

logger = logging.getLogger("hunternexus.pipeline")

# Opt-in deep-dive stages (content discovery, parameter discovery, API
# discovery) run per-live-host with genuinely heavy tools -- capped rather
# than run unbounded across every live host found, so turning one of these
# flags on doesn't silently turn a 200-host scan into an all-night run.
MAX_CONTENT_DISCOVERY_HOSTS = 10
MAX_PARAM_DISCOVERY_HOSTS = 10
MAX_API_DISCOVERY_HOSTS = 10
MAX_JS_ANALYSIS_FILES = 30
MAX_WAF_DETECT_HOSTS = 50

# Maps subdomain_passive.passive_enumerate()'s per-tool result keys to a
# matching Source enum value, so each passively-discovered asset is
# attributed to the specific tool that found it.
PASSIVE_SOURCE_MAP: dict[str, Source] = {
    "subfinder": Source.SUBFINDER,
    "amass": Source.AMASS,
    "bbot": Source.BBOT,
    "assetfinder": Source.ASSETFINDER,
    "crtsh": Source.CRTSH,
    "c99": Source.C99,
}

OnStage = Callable[[str, str, str], None]


@dataclass
class PipelineOptions:
    # --- passive subdomain discovery (cheap, default on) ------------------
    use_subfinder: bool = True
    use_amass: bool = True
    use_bbot: bool = False
    use_crtsh: bool = True
    use_assetfinder: bool = True
    use_github: bool = False

    # --- GitHub dorking / open cloud storage (need a keyword + tokens) ----
    use_gitdorker: bool = False
    gitdorker_keyword: str | None = None
    use_cloud_enum: bool = False
    cloud_enum_keyword: str | None = None

    # --- internet-wide asset intelligence (Uncover: Shodan/Censys/etc.) ---
    use_uncover: bool = False
    uncover_query: str | None = None

    # --- active subdomain discovery (expensive, default off) --------------
    use_bruteforce: bool = False
    use_permutation: bool = False
    wordlist: Path | None = None
    resolvers: Path | None = None

    # --- DNS validation (cheap, default on) --------------------------------
    use_dns_intel: bool = True

    # --- live validation enrichment ----------------------------------------
    use_tls_probe: bool = True
    use_waf_detect: bool = False
    use_favicon: bool = False
    favicon_db: Path | None = None
    use_screenshots: bool = False
    screenshot_engine: str = "gowitness"  # "gowitness" (recommended, structured output) or "go-stare" (faster, images only)

    # --- deep-dive content/endpoint discovery (expensive, default off) ----
    use_content_discovery: bool = False
    ffuf_wordlist: Path | None = None
    use_web_crawl: bool = False
    use_js_analysis: bool = False
    use_parameter_discovery: bool = False
    use_api_discovery: bool = False
    kiterunner_wordlist: str = api_discovery.DEFAULT_WORDLIST
    kiterunner_kite_file: str | None = None

    # --- scoped vulnerability verification (nuclei, watchlist CVEs only) --
    use_vuln_verify: bool = False
    use_cve_intel: bool = True  # EPSS/CISA KEV refresh before scoring -- cheap, graceful on failure

    output_dir: Path = field(default_factory=lambda: Path("./hunternexus-output"))


class Pipeline:
    def __init__(self, config: Config, options: PipelineOptions | None = None, on_stage: OnStage | None = None):
        self.config = config
        self.options = options or PipelineOptions()
        self.on_stage: OnStage = on_stage or (lambda label, status, detail: None)
        db_path = self.options.output_dir / "assets.db"
        self.store = AssetStore(db_path)

    @contextmanager
    def _stage(self, label: str):
        """Wraps one unit of work: announces it starting, times it, and
        announces completion with whatever detail string the caller sets
        on the yielded dict (`info["detail"] = ...`) before the block
        ends. A stage the caller never enters (e.g. an `if` branch for a
        disabled option) simply never gets announced -- which is exactly
        the behavior a progress UI wants."""
        self.on_stage(label, "start", "")
        t0 = time.time()
        info: dict[str, str] = {"detail": ""}
        try:
            yield info
        finally:
            elapsed = time.time() - t0
            suffix = f" -- {info['detail']}" if info["detail"] else ""
            self.on_stage(label, "done", f"{elapsed:.1f}s{suffix}")

    def run(self, target: str) -> dict:
        logger.info("starting recon pipeline for %s", target)
        scan_start = time.time()
        scan_id = self.store.start_scan(target)
        stages_run: list[str] = []
        findings: dict[str, Any] = {}

        subdomains: list[Asset] = []

        # --- passive subdomain enumeration --------------------------------
        with self._stage("Passive subdomain discovery") as info:
            passive_results = subdomain_passive.passive_enumerate(
                self.config,
                target,
                use_subfinder=self.options.use_subfinder,
                use_amass=self.options.use_amass,
                use_bbot=self.options.use_bbot,
                use_crtsh=self.options.use_crtsh,
                use_assetfinder=self.options.use_assetfinder,
            )
            for source_name, values in passive_results.items():
                stages_run.append(f"subdomain_passive:{source_name}")
                # Per-tool Source value (not the generic SUBDOMAIN_PASSIVE) so
                # the source-reliability scorecard can actually tell subfinder
                # apart from amass/bbot/assetfinder/crtsh -- passive_results is
                # already keyed by individual tool, it was just being discarded
                # here before (confirmed via a live run: the scorecard
                # only ever showed one undifferentiated "subdomain_passive"
                # bucket, never the individual tools).
                source = PASSIVE_SOURCE_MAP.get(source_name, Source.SUBDOMAIN_PASSIVE)
                for v in values:
                    subdomains.append(Asset(value=v, asset_type=AssetType.SUBDOMAIN, source=source, target=target))
            info["detail"] = f"{len(subdomains)} candidate(s) from {len(passive_results)} source(s)"

        # --- GitHub recon --------------------------------------------------
        if self.options.use_github:
            with self._stage("GitHub code-search recon") as info:
                stages_run.append("github_recon")
                found = github_recon.github_subdomains(self.config, target)
                for v in found:
                    subdomains.append(
                        Asset(value=v, asset_type=AssetType.SUBDOMAIN, source=Source.GITHUB_RECON, target=target)
                    )
                info["detail"] = f"{len(found)} candidate(s)"

        # --- GitHub dorking (secrets/sensitive files, not subdomains) ------
        if self.options.use_gitdorker and self.options.gitdorker_keyword:
            with self._stage("GitHub dorking") as info:
                stages_run.append("gitdorker")
                hits = github_recon.gitdorker_scan(self.config, self.options.gitdorker_keyword)
                findings["gitdork_hits"] = [asdict(h) for h in hits]
                logger.info("gitdorker: %d hit(s) for keyword '%s'", len(hits), self.options.gitdorker_keyword)
                info["detail"] = f"{len(hits)} hit(s)"

        # --- open/misconfigured cloud storage --------------------------------
        if self.options.use_cloud_enum and self.options.cloud_enum_keyword:
            with self._stage("Cloud storage enumeration") as info:
                stages_run.append("cloud_enum")
                hits = open_storage.cloud_enum_scan(self.config, self.options.cloud_enum_keyword)
                findings["cloud_storage_hits"] = [asdict(h) for h in hits]
                logger.info("cloud_enum: %d hit(s) for keyword '%s'", len(hits), self.options.cloud_enum_keyword)
                info["detail"] = f"{len(hits)} hit(s)"

        # --- internet-wide asset intelligence (Uncover) ---------------------
        # Returns ip:port pairs, not hostnames -- kept separate from the
        # subdomain/Asset list and folded straight into live-host probing
        # further down, since dnsx's resolution stage has nothing useful to
        # do with an address that's already an IP.
        uncover_hosts: list[str] = []
        if self.options.use_uncover:
            with self._stage("Internet-wide asset intelligence (Uncover)") as info:
                stages_run.append("uncover")
                query = self.options.uncover_query or f'hostname:"{target}"'
                uncover_hosts = internet_intel.uncover_search(self.config, query)
                findings["uncover_hosts"] = uncover_hosts
                logger.info("uncover: %d host(s) for query '%s'", len(uncover_hosts), query)
                info["detail"] = f"{len(uncover_hosts)} host(s)"

        # --- dedupe known subdomains before spending bruteforce/permutation
        # budget on them again --------------------------------------------
        subdomains = dedupe_assets(subdomains)

        # --- active bruteforce ----------------------------------------------
        if self.options.use_bruteforce and self.options.wordlist and self.options.resolvers:
            with self._stage("Subdomain bruteforce") as info:
                stages_run.append("subdomain_bruteforce")
                found = subdomain_bruteforce.bruteforce(
                    self.config, target, self.options.wordlist, self.options.resolvers
                )
                for v in found:
                    subdomains.append(
                        Asset(value=v, asset_type=AssetType.SUBDOMAIN, source=Source.SUBDOMAIN_BRUTEFORCE, target=target)
                    )
                info["detail"] = f"{len(found)} resolved hostname(s)"

        # --- permutation/alteration -----------------------------------------
        # known_values is captured HERE, after bruteforce -- not before it.
        # Capturing it earlier (the original bug, confirmed via a live
        # run) meant anything bruteforce discovered never got fed into
        # permutation's mutation engine at all, silently wasting the whole
        # stage's potential on bruteforce-found names.
        if self.options.use_permutation and self.options.resolvers:
            with self._stage("Subdomain permutation") as info:
                stages_run.append("permutation")
                known_values = [a.value for a in dedupe_assets(subdomains)] or [target]
                found = permutation.permute_and_resolve(self.config, known_values, self.options.resolvers)
                for v in found:
                    subdomains.append(
                        Asset(value=v, asset_type=AssetType.SUBDOMAIN, source=Source.PERMUTATION, target=target)
                    )
                info["detail"] = f"{len(found)} resolved hostname(s)"

        subdomains = dedupe_assets(subdomains)
        new_assets = self.store.upsert_many(subdomains)
        logger.info(
            "%d total subdomains known for %s (%d new this run)", len(subdomains), target, len(new_assets)
        )

        # --- DNS validation / wildcard filtering (dnsx) ---------------------
        # Confirms each candidate actually resolves -- and what it resolves
        # to -- BEFORE handing anything to httpx, same "don't waste a stage
        # on dead hosts" discipline as the rest of this pipeline. Candidates
        # that don't resolve are dropped here rather than silently failing
        # three stages later in httpx/tlsx/ffuf.
        candidate_hosts = [a.value for a in subdomains] or [target]
        dns_records: dict[str, dns_intel.DNSRecord] = {}
        if self.options.use_dns_intel:
            with self._stage("DNS validation (dnsx)") as info:
                stages_run.append("dns_intel")
                original_count = len(candidate_hosts)
                resolvers_str = str(self.options.resolvers) if self.options.resolvers else None
                dns_records = dns_intel.resolve_bulk(self.config, candidate_hosts, resolvers=resolvers_str)
                resolved = dns_intel.resolving_hosts_only(dns_records)
                if resolved:
                    logger.info(
                        "dns_intel: %d/%d candidate hosts actually resolve -- dropping the rest before live validation",
                        len(resolved), original_count,
                    )
                    candidate_hosts = resolved
                else:
                    logger.warning("dns_intel returned no resolving hosts (dnsx missing, or everything genuinely dead?) -- keeping the original candidate list")
                info["detail"] = f"{len(resolved)}/{original_count} resolving"

        # Uncover's ip:port candidates are already-resolved addresses --
        # folded in after DNS filtering, not before (there's nothing for
        # dnsx to resolve about an IP that's already an IP).
        all_hosts = dedupe_strings(candidate_hosts + [h.split(":")[0] for h in uncover_hosts])

        # --- live validation / tech fingerprinting --------------------------
        with self._stage("Live-host validation (httpx)") as info:
            stages_run.append("live_validation")
            live_hosts: list[LiveHost] = live_validation.probe(self.config, all_hosts)
            live_urls = [h.url for h in live_hosts]
            bare_hosts = dedupe_strings(strip_scheme(u) for u in live_urls)
            info["detail"] = f"{len(live_hosts)}/{len(all_hosts)} host(s) live"

        # --- TLS / certificate probing (tlsx) --------------------------------
        tls_info: dict[str, tls_probe.TLSInfo] = {}
        if self.options.use_tls_probe and bare_hosts:
            with self._stage("TLS/certificate probing (tlsx)") as info:
                stages_run.append("tls_probe")
                tls_info = tls_probe.probe(self.config, bare_hosts)
                info["detail"] = f"{len(tls_info)} host(s) probed"

        # --- WAF fingerprinting (wafw00f) -------------------------------------
        # Capped like the other deep-dive stages -- confirmed via a live
        # engagement run that running the full live-host list in one
        # uncapped batch let a single unreachable host burn the whole
        # stage's timeout via wafw00f's own connection retries, returning
        # zero results for every host in the batch, not just the bad one.
        waf_info: dict[str, waf_detect.WAFResult] = {}
        if self.options.use_waf_detect and live_urls:
            with self._stage("WAF fingerprinting (wafw00f)") as info:
                stages_run.append("waf_detect")
                targets = live_urls[:MAX_WAF_DETECT_HOSTS]
                if len(live_urls) > MAX_WAF_DETECT_HOSTS:
                    logger.info(
                        "waf_detect: capping wafw00f to the first %d of %d live hosts",
                        MAX_WAF_DETECT_HOSTS, len(live_urls),
                    )
                waf_info = waf_detect.detect(self.config, targets)
                detected = sum(1 for r in waf_info.values() if r.detected)
                info["detail"] = f"{detected}/{len(targets)} host(s) behind a WAF"

        # --- favicon fingerprinting ------------------------------------------
        if self.options.use_favicon and self.options.favicon_db:
            with self._stage("Favicon fingerprinting") as info:
                stages_run.append("favicon_fingerprint")
                url_hashes = {}
                for h in live_hosts:
                    hv = favicon_fingerprint.compute_hash(h.url)
                    if hv is not None:
                        h.favicon_hash = str(hv)
                        url_hashes[h.url] = hv
                matches = favicon_fingerprint.match_against_database(url_hashes, self.options.favicon_db)
                for h in live_hosts:
                    if h.url in matches:
                        h.favicon_match = matches[h.url]
                info["detail"] = f"{len(matches)} match(es)"

        # --- screenshotting ----------------------------------------------------
        if self.options.use_screenshots:
            with self._stage(f"Screenshotting ({self.options.screenshot_engine})") as info:
                stages_run.append(f"screenshotting:{self.options.screenshot_engine}")
                screenshot_dir = self.options.output_dir / "screenshots" / target
                if self.options.screenshot_engine == "go-stare":
                    screenshotting.go_stare(self.config, all_hosts, screenshot_dir)
                    info["detail"] = f"{len(all_hosts)} host(s) attempted"
                else:
                    gw_results = screenshotting.gowitness_scan(self.config, all_hosts, screenshot_dir)
                    # gowitness returns structured per-URL data (title, status,
                    # screenshot path) -- fold it straight into the matching
                    # LiveHost objects so the final report doesn't need a
                    # separate screenshot index to cross-reference by hand.
                    by_url = {r.url: r for r in gw_results}
                    for h in live_hosts:
                        gw = by_url.get(h.url)
                        if gw:
                            h.screenshot_path = gw.screenshot_path
                            if not h.title and gw.title:
                                h.title = gw.title
                    info["detail"] = f"{len(gw_results)} screenshot(s)"

        # --- content discovery (ffuf) -----------------------------------------
        if self.options.use_content_discovery and live_urls:
            with self._stage("Content discovery (ffuf)") as info:
                stages_run.append("content_discovery")
                targets = live_urls[:MAX_CONTENT_DISCOVERY_HOSTS]
                if len(live_urls) > MAX_CONTENT_DISCOVERY_HOSTS:
                    logger.info(
                        "content_discovery: capping ffuf to the first %d of %d live hosts",
                        MAX_CONTENT_DISCOVERY_HOSTS, len(live_urls),
                    )
                hits_by_host = {}
                for url in targets:
                    hits = content_discovery.fuzz(self.config, url, wordlist=self.options.ffuf_wordlist)
                    if hits:
                        hits_by_host[url] = [asdict(h) for h in hits]
                findings["content_discovery"] = hits_by_host
                total_hits = sum(len(v) for v in hits_by_host.values())
                info["detail"] = f"{total_hits} hit(s) across {len(targets)} host(s)"

        # --- web crawling + historical URL mining (katana, gau) ---------------
        crawled_urls: list[str] = []
        if self.options.use_web_crawl:
            with self._stage("Web crawling + historical URLs (katana, gau)") as info:
                stages_run.append("web_crawl")
                katana_urls = web_crawl.katana_crawl(self.config, live_urls) if live_urls else []
                gau_urls = web_crawl.gau_historical(self.config, target)
                crawled_urls = dedupe_strings(katana_urls + gau_urls)
                findings["crawled_urls"] = crawled_urls
                info["detail"] = f"{len(crawled_urls)} URL(s)"

        # --- JS analysis: endpoints, secrets, source maps ----------------------
        if self.options.use_js_analysis and crawled_urls:
            with self._stage("JavaScript analysis") as info:
                stages_run.append("js_analysis")
                js_urls = [u for u in crawled_urls if u.split("?")[0].endswith(".js")][:MAX_JS_ANALYSIS_FILES]

                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
                    tmp.write("\n".join(crawled_urls))
                    crawl_list_path = Path(tmp.name)
                endpoints = js_analysis.xnlinkfinder_extract(self.config, str(crawl_list_path), scope_filter=target)
                crawl_list_path.unlink(missing_ok=True)

                secrets = []
                for js_url in js_urls:
                    secrets.extend(asdict(s) for s in js_analysis.secretfinder_extract(self.config, js_url))
                source_maps = js_analysis.discover_source_maps(js_urls)

                findings["js_analysis"] = {"endpoints": endpoints, "secrets": secrets, "source_maps": source_maps}
                info["detail"] = f"{len(endpoints)} endpoint(s), {len(secrets)} secret lead(s), {len(source_maps)} source map(s)"

        # --- hidden parameter discovery (Arjun + x8) ---------------------------
        if self.options.use_parameter_discovery and live_urls:
            with self._stage("Parameter discovery (Arjun + x8)") as info:
                stages_run.append("parameter_discovery")
                targets = live_urls[:MAX_PARAM_DISCOVERY_HOSTS]
                if len(live_urls) > MAX_PARAM_DISCOVERY_HOSTS:
                    logger.info(
                        "parameter_discovery: capping Arjun+x8 to the first %d of %d live hosts",
                        MAX_PARAM_DISCOVERY_HOSTS, len(live_urls),
                    )
                findings["parameter_discovery"] = {
                    url: parameter_discovery.discover_both(self.config, url) for url in targets
                }
                info["detail"] = f"{len(targets)} host(s) tested"

        # --- API route discovery (Kiterunner) -----------------------------------
        if self.options.use_api_discovery and live_urls:
            with self._stage("API route discovery (Kiterunner)") as info:
                stages_run.append("api_discovery")
                targets = live_urls[:MAX_API_DISCOVERY_HOSTS]
                if len(live_urls) > MAX_API_DISCOVERY_HOSTS:
                    logger.info(
                        "api_discovery: capping Kiterunner to the first %d of %d live hosts",
                        MAX_API_DISCOVERY_HOSTS, len(live_urls),
                    )
                hits_by_host = {}
                for url in targets:
                    hits = api_discovery.scan(
                        self.config, url,
                        wordlist=self.options.kiterunner_wordlist,
                        custom_kite_file=self.options.kiterunner_kite_file,
                    )
                    if hits:
                        hits_by_host[url] = [asdict(h) for h in hits]
                findings["api_discovery"] = hits_by_host
                total_hits = sum(len(v) for v in hits_by_host.values())
                info["detail"] = f"{total_hits} route(s) across {len(targets)} host(s)"

        # --- CVE intel refresh (EPSS / CISA KEV), before scoring ----------------
        if self.options.use_cve_intel:
            with self._stage("CVE intel refresh (EPSS / CISA KEV)") as info:
                stages_run.append("cve_intel_refresh")
                try:
                    prioritize.refresh_cve_intel()
                    info["detail"] = "ok"
                except Exception as e:
                    logger.warning("CVE intel refresh failed (%s) -- scoring proceeds without EPSS/KEV enhancement", e)
                    info["detail"] = "failed, proceeding without enhancement"

        # --- scoring / prioritization ---------------------------------------
        with self._stage("Risk scoring") as info:
            stages_run.append("scoring")
            ranked_hosts = rank(live_hosts)
            info["detail"] = f"{len(ranked_hosts)} host(s) scored"

        # --- scoped vulnerability verification (nuclei, watchlist CVEs only) ---
        # Deliberately only ever run against hosts scoring.prioritize already
        # flagged as matching an edge-device CVE watchlist product -- never
        # the whole live-host list indiscriminately (see vuln_verify.py).
        if self.options.use_vuln_verify:
            watchlist_hosts = [
                strip_scheme(h.url) for h in ranked_hosts
                if any("edge-device CVE watchlist" in r for r in h.risk_reasons)
            ]
            if watchlist_hosts:
                with self._stage("Scoped CVE verification (nuclei)") as info:
                    stages_run.append("vuln_verify")
                    verified = vuln_verify.verify_watchlist(self.config, watchlist_hosts)
                    findings["vuln_verify"] = [asdict(v) for v in verified]
                    info["detail"] = f"{len(verified)} confirmed finding(s) on {len(watchlist_hosts)} flagged host(s)"

        # --- architecture / tech-detection report (separate file) --------------
        with self._stage("Architecture report") as info:
            stages_run.append("architecture_report")
            arch_rows = architecture.build(live_hosts, tls_info=tls_info, waf_info=waf_info, dns_records=dns_records)
            arch_path = architecture.export_markdown(
                target, arch_rows, self.options.output_dir / f"{target}-architecture.md"
            )
            info["detail"] = arch_path.name

        # --- export (ranked worklist) --------------------------------------
        with self._stage("Report export") as info:
            stages_run.append("export")
            json_path = export.export_json(
                target, new_assets_as_dicts(new_assets), ranked_hosts, self.options.output_dir / f"{target}.json"
            )
            md_path = export.export_markdown(
                target, new_assets_as_dicts(new_assets), ranked_hosts, self.options.output_dir / f"{target}.md"
            )
            info["detail"] = f"{json_path.name}, {md_path.name}"

        # --- auxiliary deep-dive findings (kept separate from the ranked
        # worklist -- raw tool output, not re-scored/re-ranked) -------------
        findings_path = None
        if findings:
            findings_path = self.options.output_dir / f"{target}-findings.json"
            findings_path.parent.mkdir(parents=True, exist_ok=True)
            findings_path.write_text(json.dumps(findings, indent=2, default=str))

        self.store.finish_scan(scan_id, stages_run)
        elapsed = time.time() - scan_start
        logger.info("pipeline finished for %s in %.1fs -- stages: %s", target, elapsed, ", ".join(stages_run))

        return {
            "target": target,
            "elapsed_seconds": elapsed,
            "stages_run": stages_run,
            "total_subdomains": len(subdomains),
            "new_assets": len(new_assets),
            "live_hosts": len(live_hosts),
            "json_report": str(json_path),
            "markdown_report": str(md_path),
            "architecture_report": str(arch_path),
            "findings_report": str(findings_path) if findings_path else None,
        }

    def change_report(self, target: str, since_epoch: float) -> list[dict]:
        """The 'attack-surface growth tracker' capability: what's appeared
        for this target since an arbitrary past timestamp (e.g. the start
        of the last scan), independent of running a new scan."""
        return self.store.new_since(target, since_epoch)

    def source_reliability(self, target: str | None = None) -> dict[str, int]:
        """The 'recon-source reliability scorecard' capability."""
        return self.store.source_reliability(target)

    def close(self) -> None:
        self.store.close()


def new_assets_as_dicts(assets: list[Asset]) -> list[dict]:
    return [
        {"value": a.value, "asset_type": a.asset_type.value, "sources": a.metadata.get("also_found_by", [a.source.value])}
        for a in assets
    ]
