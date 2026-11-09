"""Interactive pre-flight wizard for `hunternexus run`.

Collects exactly what's needed to run a scan smoothly -- target(s), an
explicit authorization confirmation, a depth preset (or a fully custom
stage selection), and whatever supplementary input each enabled stage
actually requires (wordlists, keywords) -- before any tool runs, rather
than discovering mid-scan that a required flag was missing.
"""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from hunternexus.pipeline import PipelineOptions

PRESET_QUICK = "quick"
PRESET_STANDARD = "standard"
PRESET_FULL = "full"
PRESET_ADVANCED = "advanced"


def _abort(console: Console, message: str) -> None:
    console.print(f"\n[bold red]✗ {message}[/]\n")
    sys.exit(1)


def prompt_targets(console: Console) -> list[str]:
    console.print("[bold]Target[/]")
    console.print(
        "  Enter a single domain, a comma-separated list, or the path to a\n"
        "  text file with one domain per line.",
        style="dim",
    )
    raw = Prompt.ask("  [cyan]Target(s)[/]").strip()
    if not raw:
        _abort(console, "No target provided.")

    candidate_path = Path(raw).expanduser()
    if candidate_path.is_file():
        domains = [
            line.strip()
            for line in candidate_path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not domains:
            _abort(console, f"{candidate_path} exists but contains no domains.")
        console.print(f"  [dim]Loaded {len(domains)} domain(s) from {candidate_path}[/]")
        return domains

    domains = [d.strip() for d in raw.split(",") if d.strip()]
    if not domains:
        _abort(console, "No valid domain(s) parsed from input.")
    return domains


def prompt_authorization(console: Console, targets: list[str]) -> None:
    console.print()
    console.print(
        Panel(
            "hunterNexus is built for [bold]authorized security testing only[/] -- "
            "a bug bounty program you're enrolled in, or infrastructure you own "
            "or have explicit written permission to test.\n\n"
            "Target(s):\n" + "\n".join(f"  • {t}" for t in targets),
            title="[bold yellow]Authorization[/]",
            border_style="yellow",
        )
    )
    if not Confirm.ask("  [bold]Confirm you are authorized to test the target(s) above[/]", default=False):
        _abort(console, "Not confirmed -- aborting. Only scan targets you're authorized to test.")


def prompt_preset(console: Console) -> str:
    console.print()
    console.print("[bold]Scan depth[/]")
    table = Table(show_header=True, header_style="bold cyan", box=None, padding=(0, 2, 0, 0))
    table.add_column("Preset")
    table.add_column("What it runs")
    table.add_row("quick", "Passive discovery, DNS/TLS validation, live-host triage, scoring. No active traffic beyond liveness checks.")
    table.add_row("standard", "Quick + GitHub recon, WAF detection, screenshots, crawling + JS analysis.")
    table.add_row("full", "Every stage: GitDorker, cloud_enum, Uncover, bruteforce/permutation, content discovery, parameter/API discovery, scoped CVE verification.")
    table.add_row("advanced", "Choose each stage individually.")
    console.print(table)
    return Prompt.ask(
        "  [cyan]Preset[/]",
        choices=[PRESET_QUICK, PRESET_STANDARD, PRESET_FULL, PRESET_ADVANCED],
        default=PRESET_STANDARD,
    )


def _prompt_existing_path(console: Console, label: str, required: bool) -> Path | None:
    while True:
        value = Prompt.ask(f"  [cyan]{label}[/]" + ("" if required else " [dim](leave blank to skip)[/]")).strip()
        if not value:
            if required:
                console.print("  [red]A path is required for this stage.[/]")
                continue
            return None
        path = Path(value).expanduser()
        if not path.is_file():
            console.print(f"  [red]{path} does not exist.[/] Try again.")
            continue
        return path


def _prompt_keyword(console: Console, label: str) -> str:
    console.print(f"  [dim]{label} -- usually the org/company name, not the domain (e.g. 'acme', not 'acme.com').[/]")
    value = Prompt.ask("  [cyan]Keyword[/]").strip()
    while not value:
        console.print("  [red]A keyword is required for this stage.[/]")
        value = Prompt.ask("  [cyan]Keyword[/]").strip()
    return value


def _toggle(console: Console, label: str, help_text: str, default: bool = False) -> bool:
    console.print(f"  [dim]{help_text}[/]")
    return Confirm.ask(f"  [cyan]{label}[/]", default=default)


def build_options(console: Console, preset: str, output_dir: Path) -> PipelineOptions:
    opts = PipelineOptions(output_dir=output_dir)

    if preset == PRESET_QUICK:
        return opts

    if preset == PRESET_STANDARD:
        opts.use_github = True
        opts.use_waf_detect = True
        opts.use_screenshots = True
        opts.use_web_crawl = True
        opts.use_js_analysis = True
        return opts

    if preset == PRESET_FULL:
        opts.use_github = True
        opts.use_waf_detect = True
        opts.use_screenshots = True
        opts.use_web_crawl = True
        opts.use_js_analysis = True
        opts.use_content_discovery = True
        opts.use_parameter_discovery = True
        opts.use_api_discovery = True
        opts.use_vuln_verify = True

        console.print()
        console.print("[bold]Full scan -- additional input needed[/]")

        opts.use_gitdorker = Confirm.ask("  [cyan]Run GitHub dorking (GitDorker)?[/]", default=True)
        if opts.use_gitdorker:
            opts.gitdorker_keyword = _prompt_keyword(console, "GitDorker")

        opts.use_cloud_enum = Confirm.ask("  [cyan]Run cloud storage bucket enumeration?[/]", default=True)
        if opts.use_cloud_enum:
            opts.cloud_enum_keyword = _prompt_keyword(console, "cloud_enum")

        opts.use_uncover = Confirm.ask("  [cyan]Query Shodan/Censys/etc. via Uncover?[/]", default=True)

        if Confirm.ask("  [cyan]Run subdomain bruteforce + permutation?[/]", default=True):
            console.print("  [dim]Needs a subdomain wordlist, e.g. SecLists' Discovery/DNS/subdomains-top1million-20000.txt[/]")
            wordlist = _prompt_existing_path(console, "Wordlist path", required=True)
            opts.use_bruteforce = True
            opts.use_permutation = True
            opts.wordlist = wordlist

        console.print("  [dim]Content discovery needs a web-path wordlist, e.g. SecLists' Discovery/Web-Content/common.txt[/]")
        opts.ffuf_wordlist = _prompt_existing_path(console, "ffuf wordlist path", required=True)

        return opts

    # PRESET_ADVANCED -- walk every toggle individually
    console.print()
    console.print("[bold]Advanced -- choose each stage[/]")

    opts.use_subfinder = _toggle(console, "subfinder", "Passive subdomain enumeration.", True)
    opts.use_amass = _toggle(console, "amass", "Passive subdomain enumeration (can be slow on large targets).", True)
    opts.use_bbot = _toggle(console, "bbot", "Passive subdomain enumeration via BBOT.", False)
    opts.use_crtsh = _toggle(console, "crt.sh", "Certificate-transparency subdomain lookup.", True)
    opts.use_assetfinder = _toggle(console, "assetfinder", "Passive subdomain enumeration.", True)
    opts.use_github = _toggle(console, "GitHub recon", "GitHub code search for subdomain mentions (needs a token).", False)

    opts.use_gitdorker = _toggle(console, "GitDorker", "GitHub dorking for secrets/sensitive files (needs a token + keyword).", False)
    if opts.use_gitdorker:
        opts.gitdorker_keyword = _prompt_keyword(console, "GitDorker")

    opts.use_cloud_enum = _toggle(console, "cloud_enum", "Brute-force AWS/Azure/GCP storage names (needs a keyword).", False)
    if opts.use_cloud_enum:
        opts.cloud_enum_keyword = _prompt_keyword(console, "cloud_enum")

    opts.use_uncover = _toggle(console, "Uncover", "Query Shodan/Censys/etc. in one pass.", False)

    if _toggle(console, "bruteforce + permutation", "Active subdomain discovery -- needs a wordlist.", False):
        wordlist = _prompt_existing_path(console, "Subdomain wordlist path", required=True)
        opts.use_bruteforce = True
        opts.use_permutation = True
        opts.wordlist = wordlist

    opts.use_dns_intel = _toggle(console, "DNS validation (dnsx)", "Resolve + wildcard-filter candidates before live validation.", True)
    opts.use_tls_probe = _toggle(console, "TLS probing (tlsx)", "Certificate/TLS misconfiguration checks on live hosts.", True)
    opts.use_waf_detect = _toggle(console, "WAF detection", "Sends WAF-triggering probe requests to live hosts.", False)

    if _toggle(console, "favicon fingerprinting", "Needs a favicon-hash database file.", False):
        favicon_db = _prompt_existing_path(console, "Favicon database path", required=True)
        opts.use_favicon = True
        opts.favicon_db = favicon_db

    opts.use_screenshots = _toggle(console, "screenshots", "Capture every live host visually.", False)

    if _toggle(console, "content discovery (ffuf)", "Directory/file fuzzing -- needs a web-path wordlist.", False):
        ffuf_wordlist = _prompt_existing_path(console, "ffuf wordlist path", required=True)
        opts.use_content_discovery = True
        opts.ffuf_wordlist = ffuf_wordlist

    opts.use_web_crawl = _toggle(console, "web crawl (Katana + gau)", "Crawl live hosts and mine historical URLs.", False)
    opts.use_js_analysis = _toggle(console, "JS analysis", "Endpoint/secret/source-map extraction from crawled JS (needs web crawl).", False)
    opts.use_parameter_discovery = _toggle(console, "parameter discovery", "Hidden parameter discovery (Arjun + x8).", False)
    opts.use_api_discovery = _toggle(console, "API discovery", "API route brute-forcing (Kiterunner).", False)
    opts.use_vuln_verify = _toggle(console, "scoped CVE verification", "nuclei, restricted to the exact edge-device CVE watchlist.", False)
    opts.use_cve_intel = _toggle(console, "EPSS/CISA-KEV enrichment", "Live scoring enhancement before ranking.", True)

    return opts


def confirm_summary(console: Console, targets: list[str], preset: str, opts: PipelineOptions) -> None:
    enabled = []
    for field_name in (
        "use_github", "use_gitdorker", "use_cloud_enum", "use_uncover", "use_bruteforce",
        "use_permutation", "use_waf_detect", "use_favicon", "use_screenshots",
        "use_content_discovery", "use_web_crawl", "use_js_analysis",
        "use_parameter_discovery", "use_api_discovery", "use_vuln_verify",
    ):
        if getattr(opts, field_name):
            enabled.append(field_name.removeprefix("use_"))

    console.print()
    table = Table(title="Run summary", show_header=False, box=None)
    table.add_row("[bold]Target(s)[/]", ", ".join(targets))
    table.add_row("[bold]Preset[/]", preset)
    table.add_row("[bold]Extra stages[/]", ", ".join(enabled) if enabled else "[dim]none (quick defaults only)[/]")
    table.add_row("[bold]Output directory[/]", str(opts.output_dir))
    console.print(table)
    console.print()
    if not Confirm.ask("[bold]Proceed?[/]", default=True):
        _abort(console, "Cancelled.")
