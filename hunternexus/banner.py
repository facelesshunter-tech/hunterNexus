"""Startup banner for the `hunternexus run` guided experience.

Kept as its own module (not inlined into cli.py) so the branding is one
place to edit, and so tests/other callers can import `print_banner`
without pulling in the full interactive wizard.
"""

from __future__ import annotations

from rich.console import Console

from hunternexus import __version__

_LOGO = r"""
    __                __            _   __
   / /_  __  ______  / /____  _____/ | / /__  _  ____  _______
  / __ \/ / / / __ \/ __/ _ \/ ___/  |/ / _ \| |/_/ / / / ___/
 / / / / /_/ / / / / /_/  __/ /  / /|  /  __/>  </ /_/ (__  )
/_/ /_/\__,_/_/ /_/\__/\___/_/  /_/ |_/\___/_/|_|\__,_/____/
""".strip("\n")


def print_banner(console: Console) -> None:
    console.print()
    console.print(_LOGO, style="bold green", highlight=False)
    console.print(
        f"  [bold cyan]Staged Reconnaissance Framework[/]  [dim]v{__version__}[/]",
    )
    console.print("  [dim]for authorized security testing & bug bounty engagements[/]")
    console.print()
    console.print("  [bold white]Built by Emmanuel Uwa[/] [dim]([/][bold green]Faceless Hunter[/][dim])[/]")
    console.print("  [dim]github.com/facelesshunter-tech  ·  linkedin.com/in/emmanuel-uwa-091992195[/]")
    console.rule(style="green")
    console.print()
