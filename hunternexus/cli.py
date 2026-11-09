"""hunternexus CLI.

    hunternexus scan example.com
    hunternexus scan example.com --github --bruteforce --wordlist words.txt --resolvers resolvers.txt
    hunternexus changes example.com --since-hours 24
    hunternexus sources --target example.com
    hunternexus config-check
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click

from hunternexus.config import Config
from hunternexus.pipeline import Pipeline, PipelineOptions
from hunternexus.utils.logging import setup_logging


@click.group()
@click.option("--config", "config_path", default=None, help="Path to config.yaml (default: ~/.config/hunternexus/config.yaml)")
@click.option("--verbose", "-v", is_flag=True)
@click.pass_context
def cli(ctx, config_path, verbose):
    setup_logging(verbose)
    ctx.ensure_object(dict)
    ctx.obj["config"] = Config.load(config_path)


@cli.command()
@click.argument("target")
# --- passive subdomain discovery (cheap, on by default) -------------------
@click.option("--subfinder/--no-subfinder", default=True)
@click.option("--amass/--no-amass", default=True)
@click.option("--bbot/--no-bbot", default=False)
@click.option("--crtsh/--no-crtsh", default=True)
@click.option("--assetfinder/--no-assetfinder", default=True)
@click.option("--github", "use_github", is_flag=True, default=False, help="Run github-subdomains (needs GitHub tokens configured)")
# --- GitHub dorking / open cloud storage -----------------------------------
@click.option("--gitdorker", "use_gitdorker", is_flag=True, default=False, help="Run GitDorker (needs GitHub tokens + --gitdorker-keyword)")
@click.option("--gitdorker-keyword", default=None, help="Keyword for GitDorker (usually the org/company name)")
@click.option("--cloud-enum", "use_cloud_enum", is_flag=True, default=False, help="Brute-force AWS/Azure/GCP storage names (needs --cloud-enum-keyword)")
@click.option("--cloud-enum-keyword", default=None, help="Keyword for cloud_enum (usually the org/company name)")
# --- internet-wide asset intelligence --------------------------------------
@click.option("--uncover", "use_uncover", is_flag=True, default=False, help="Query Shodan/Censys/etc. via Uncover (needs API keys configured)")
@click.option("--uncover-query", default=None, help='Uncover query (default: hostname:"<target>")')
# --- active subdomain discovery (expensive, off by default) ---------------
@click.option("--bruteforce", "use_bruteforce", is_flag=True, default=False)
@click.option("--permutation", "use_permutation", is_flag=True, default=False)
@click.option("--wordlist", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--resolvers", type=click.Path(exists=True, path_type=Path), default=None)
# --- DNS validation ----------------------------------------------------------
@click.option("--dns-intel/--no-dns-intel", default=True, help="Resolve + wildcard-filter candidates with dnsx before live validation")
# --- live validation enrichment --------------------------------------------
@click.option("--tls-probe/--no-tls-probe", default=True, help="Probe live hosts' TLS/certs with tlsx (feeds the architecture report)")
@click.option("--waf-detect", "use_waf_detect", is_flag=True, default=False, help="Fingerprint WAFs with wafw00f (sends attack-pattern probes)")
@click.option("--favicon", "use_favicon", is_flag=True, default=False)
@click.option("--favicon-db", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--screenshots", is_flag=True, default=False)
@click.option(
    "--screenshot-engine",
    type=click.Choice(["gowitness", "go-stare"]),
    default="gowitness",
    help="gowitness (default): structured output, feeds titles/screenshot paths back into the report. go-stare: faster, images only.",
)
# --- deep-dive content/endpoint discovery (expensive, off by default) -----
@click.option("--content-discovery", "use_content_discovery", is_flag=True, default=False, help="Fuzz directories/files on live hosts with ffuf")
@click.option("--ffuf-wordlist", type=click.Path(exists=True, path_type=Path), default=None)
@click.option("--web-crawl", "use_web_crawl", is_flag=True, default=False, help="Crawl live hosts (Katana) and mine historical URLs (gau)")
@click.option("--js-analysis", "use_js_analysis", is_flag=True, default=False, help="Extract endpoints/secrets/source maps from crawled JS (needs --web-crawl)")
@click.option("--parameter-discovery", "use_parameter_discovery", is_flag=True, default=False, help="Discover hidden params on live hosts with Arjun + x8")
@click.option("--api-discovery", "use_api_discovery", is_flag=True, default=False, help="Brute-force API routes on live hosts with Kiterunner")
# --- scoped vulnerability verification --------------------------------------
@click.option("--vuln-verify", "use_vuln_verify", is_flag=True, default=False, help="Run nuclei, scoped to exactly the edge-device CVE watchlist, against matching hosts")
@click.option("--cve-intel/--no-cve-intel", default=True, help="Enrich watchlist scoring with live EPSS/CISA-KEV data before ranking")
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("./hunternexus-output"))
@click.pass_context
def scan(
    ctx,
    target,
    subfinder,
    amass,
    bbot,
    crtsh,
    assetfinder,
    use_github,
    use_gitdorker,
    gitdorker_keyword,
    use_cloud_enum,
    cloud_enum_keyword,
    use_uncover,
    uncover_query,
    use_bruteforce,
    use_permutation,
    wordlist,
    resolvers,
    dns_intel,
    tls_probe,
    use_waf_detect,
    use_favicon,
    favicon_db,
    screenshots,
    screenshot_engine,
    use_content_discovery,
    ffuf_wordlist,
    use_web_crawl,
    use_js_analysis,
    use_parameter_discovery,
    use_api_discovery,
    use_vuln_verify,
    cve_intel,
    output_dir,
):
    """Run the full recon pipeline against TARGET (an apex domain)."""
    config: Config = ctx.obj["config"]

    if (use_bruteforce or use_permutation) and resolvers is None:
        from hunternexus.modules.subdomain_bruteforce import fetch_resolvers

        output_dir.mkdir(parents=True, exist_ok=True)
        resolvers = output_dir / "resolvers.txt"
        click.echo(f"No --resolvers given; fetching trickest/resolvers to {resolvers} ...")
        try:
            fetch_resolvers(resolvers)
        except Exception as e:
            click.echo(f"Failed to fetch resolvers ({e}); bruteforce/permutation will be skipped.", err=True)
            resolvers = None

    options = PipelineOptions(
        use_subfinder=subfinder,
        use_amass=amass,
        use_bbot=bbot,
        use_crtsh=crtsh,
        use_assetfinder=assetfinder,
        use_github=use_github,
        use_gitdorker=use_gitdorker,
        gitdorker_keyword=gitdorker_keyword,
        use_cloud_enum=use_cloud_enum,
        cloud_enum_keyword=cloud_enum_keyword,
        use_uncover=use_uncover,
        uncover_query=uncover_query,
        use_bruteforce=use_bruteforce,
        use_permutation=use_permutation,
        wordlist=wordlist,
        resolvers=resolvers,
        use_dns_intel=dns_intel,
        use_tls_probe=tls_probe,
        use_waf_detect=use_waf_detect,
        use_favicon=use_favicon,
        favicon_db=favicon_db,
        use_screenshots=screenshots,
        screenshot_engine=screenshot_engine,
        use_content_discovery=use_content_discovery,
        ffuf_wordlist=ffuf_wordlist,
        use_web_crawl=use_web_crawl,
        use_js_analysis=use_js_analysis,
        use_parameter_discovery=use_parameter_discovery,
        use_api_discovery=use_api_discovery,
        use_vuln_verify=use_vuln_verify,
        use_cve_intel=cve_intel,
        output_dir=output_dir,
    )
    pipeline = Pipeline(config, options)
    try:
        result = pipeline.run(target)
    finally:
        pipeline.close()

    click.echo(f"\nDone: {result['total_subdomains']} subdomains known ({result['new_assets']} new), "
               f"{result['live_hosts']} live hosts, {result['elapsed_seconds']:.1f}s")
    click.echo(f"JSON report:          {result['json_report']}")
    click.echo(f"Markdown report:      {result['markdown_report']}")
    click.echo(f"Architecture report:  {result['architecture_report']}")
    if result['findings_report']:
        click.echo(f"Deep-dive findings:   {result['findings_report']}")


@cli.command()
@click.argument("target")
@click.option("--since-hours", type=float, default=24.0, help="Report assets first seen in the last N hours")
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("./hunternexus-output"))
@click.pass_context
def changes(ctx, target, since_hours, output_dir):
    """Report assets discovered for TARGET since N hours ago -- the
    attack-surface-growth-tracker capability. Run `scan` periodically
    first; this just reads what's already stored."""
    config: Config = ctx.obj["config"]
    pipeline = Pipeline(config, PipelineOptions(output_dir=output_dir))
    try:
        since = time.time() - since_hours * 3600
        new = pipeline.change_report(target, since)
    finally:
        pipeline.close()

    if not new:
        click.echo(f"No new assets for {target} in the last {since_hours} hours.")
        return
    click.echo(f"{len(new)} new asset(s) for {target} since {since_hours} hours ago:")
    for a in new:
        click.echo(f"  [{a['asset_type']}] {a['value']}  (via: {', '.join(a['sources'])})")


@cli.command()
@click.option("--target", default=None, help="Limit to one target; omit for all targets")
@click.option("--output-dir", type=click.Path(path_type=Path), default=Path("./hunternexus-output"))
@click.pass_context
def sources(ctx, target, output_dir):
    """Show the recon-source reliability scorecard: how many assets each
    technique has contributed so far."""
    config: Config = ctx.obj["config"]
    pipeline = Pipeline(config, PipelineOptions(output_dir=output_dir))
    try:
        counts = pipeline.source_reliability(target)
    finally:
        pipeline.close()

    if not counts:
        click.echo("No data yet -- run `scan` first.")
        return
    for source_name, count in counts.items():
        click.echo(f"  {source_name:<28} {count}")


@cli.command("config-check")
@click.pass_context
def config_check(ctx):
    """Report which API-gated sources and external tools are currently
    configured/available, so you can see what `scan` will and won't use."""
    config: Config = ctx.obj["config"]

    api_sources = [
        "chaos", "github", "shodan", "c99", "whoxy", "whoisxmlapi", "hostio",
        "securitytrails", "crunchbase", "openai", "builtwith", "censys", "urlscan",
        "greyhatwarfare",
    ]
    click.echo("API keys:")
    for s in api_sources:
        status = "configured" if config.has(s) else "missing"
        click.echo(f"  {s:<16} {status}")

    tools = [
        "subfinder", "amass", "bbot", "assetfinder", "puredns", "dnsgen", "alterx", "naabu",
        "rustscan", "smap", "httpx", "dnsx", "tlsx", "wafw00f", "uncover",
        "go-stare", "gowitness", "eyewitness", "docker",
        "VHostScan", "github-subdomains", "gitdorker", "trufflehog", "favfreak", "waymore",
        "cloud_enum", "ffuf", "katana", "gau", "xnLinkFinder", "secretfinder",
        "arjun", "x8", "kr", "nuclei",
    ]
    click.echo("\nExternal tools:")
    for t in tools:
        status = config.tool_path(t) or "not found on PATH"
        click.echo(f"  {t:<20} {status}")

    if config.path:
        click.echo(f"\nConfig file: {config.path}")
    else:
        click.echo("\nNo config file found -- running with defaults/env vars only. "
                    "See config/config.example.yaml.")


def main():
    cli(obj={})


if __name__ == "__main__":
    sys.exit(main())
