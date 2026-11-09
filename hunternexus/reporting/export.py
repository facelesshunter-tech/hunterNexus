"""Structured output.

The underlying note-taking philosophy is "site-hierarchy, tool output,
interesting notes," organized by domain with a status legend (no vulns /
in progress / vulns found / completed). This module produces that same
information as a flat, scriptable JSON/Markdown export rather than a
mind-map file, since that's what downstream tooling (and a human skimming
results) actually needs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from hunternexus.models import LiveHost


def export_json(target: str, new_assets: list[dict], ranked_hosts: list[LiveHost], out_path: Path) -> Path:
    payload = {
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "new_assets_this_run": new_assets,
        "ranked_hosts": [h.to_dict() for h in ranked_hosts],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2))
    return out_path


def export_markdown(target: str, new_assets: list[dict], ranked_hosts: list[LiveHost], out_path: Path) -> Path:
    lines = [f"# Recon Report — {target}", "", f"Generated: {datetime.now(timezone.utc).isoformat()}", ""]

    lines.append(f"## New assets this run ({len(new_assets)})")
    lines.append("")
    if new_assets:
        lines.append("| Asset | Type | Source(s) |")
        lines.append("|---|---|---|")
        for a in new_assets:
            sources = ", ".join(a.get("sources", []))
            lines.append(f"| {a['value']} | {a['asset_type']} | {sources} |")
    else:
        lines.append("_No new assets since the last run._")
    lines.append("")

    lines.append(f"## Ranked live hosts ({len(ranked_hosts)})")
    lines.append("")
    lines.append("| Score | URL | Status | Title | Tech | Screenshot | Reasons |")
    lines.append("|---|---|---|---|---|---|---|")
    for h in ranked_hosts:
        reasons = "; ".join(h.risk_reasons) if h.risk_reasons else ""
        tech = ", ".join(h.tech) if h.tech else ""
        screenshot = h.screenshot_path or ""
        lines.append(
            f"| {h.risk_score:.1f} | {h.url} | {h.status_code} | {h.title or ''} | {tech} | {screenshot} | {reasons} |"
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines))
    return out_path
