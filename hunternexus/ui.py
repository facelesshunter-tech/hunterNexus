"""Live stage-progress display for the `hunternexus run` guided experience.

Wraps a `rich.status.Status` spinner around every pipeline stage so a
long-running external tool never looks like it's hung -- the animated
spinner is visible proof the process is still alive, and each stage
transition is announced on its own line before and after it runs.
"""

from __future__ import annotations

from rich.console import Console

from hunternexus.pipeline import PipelineOptions


class StageReporter:
    """Implements the `on_stage(label, status, detail)` callback
    interface `Pipeline.run()` expects. One instance is meant to cover
    one target's scan; create a fresh one per target in a multi-domain
    run so the stage counter resets for each."""

    def __init__(self, console: Console, total_estimate: int | None = None):
        self.console = console
        self.total_estimate = total_estimate
        self._count = 0
        self._status = None

    def callback(self, label: str, status: str, detail: str) -> None:
        if status == "start":
            self._count += 1
            counter = f"[{self._count}/{self.total_estimate}]" if self.total_estimate else f"[{self._count}]"
            self.console.print(f"[bold cyan]▶ STAGE {counter}[/]  [white]{label}[/]")
            self._status = self.console.status("[green]working...[/]", spinner="dots")
            self._status.start()
        elif status == "done":
            if self._status:
                self._status.stop()
                self._status = None
            self.console.print(f"  [bold green]✓[/] {label}  [dim]({detail})[/]")


def estimate_stage_count(options: PipelineOptions) -> int:
    """A best-effort count of how many stages will actually announce
    themselves, used only for the "[N/total]" display -- purely
    cosmetic, since a handful of stages (vuln_verify, parts of DNS/live
    validation) depend on runtime data this can't know in advance."""
    count = 1  # passive discovery (always runs)
    if options.use_github:
        count += 1
    if options.use_gitdorker and options.gitdorker_keyword:
        count += 1
    if options.use_cloud_enum and options.cloud_enum_keyword:
        count += 1
    if options.use_uncover:
        count += 1
    if options.use_bruteforce and options.wordlist and options.resolvers:
        count += 1
    if options.use_permutation and options.resolvers:
        count += 1
    if options.use_dns_intel:
        count += 1
    count += 1  # live validation (always runs)
    if options.use_tls_probe:
        count += 1
    if options.use_waf_detect:
        count += 1
    if options.use_favicon and options.favicon_db:
        count += 1
    if options.use_screenshots:
        count += 1
    if options.use_content_discovery:
        count += 1
    if options.use_web_crawl:
        count += 1
    if options.use_js_analysis:
        count += 1
    if options.use_parameter_discovery:
        count += 1
    if options.use_api_discovery:
        count += 1
    if options.use_cve_intel:
        count += 1
    count += 1  # scoring (always runs)
    if options.use_vuln_verify:
        count += 1  # best-effort -- may not fire if nothing matched the watchlist
    count += 2  # architecture report + export (always run)
    return count
