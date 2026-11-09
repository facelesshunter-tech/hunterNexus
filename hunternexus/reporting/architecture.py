"""The architecture / tech-detection report -- a SEPARATE file from the
main scan report (export.py's JSON/Markdown), by explicit request.

Where export.py's report answers "what's new and what's worth looking at
first," this one answers a different question: "what does this target's
infrastructure actually look like" -- one row per live host, every piece
of tech-detection data hunternexus gathered about it in one place
(httpx's tech-detect, tlsx's TLS/cert info, WAF detection, favicon
fingerprint match), plus a rollup of the ASN/IP ownership and DNS record
data behind the hosts that have it. It's the "map of the building," not
the "list of things to check first."
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from hunternexus.models import LiveHost
from hunternexus.modules.tls_probe import TLSInfo
from hunternexus.modules.waf_detect import WAFResult
from hunternexus.modules.dns_intel import DNSRecord
from hunternexus.utils.http import strip_scheme


@dataclass
class HostArchitecture:
    """One consolidated row per live host -- every tech-detection signal
    hunternexus has about it, gathered from whichever modules ran."""

    url: str
    ip: str = ""
    status_code: int | None = None
    title: str = ""
    tech: list[str] = field(default_factory=list)
    tls_version: str = ""
    jarm_hash: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_misconfigurations: list[str] = field(default_factory=list)
    waf: str = ""
    favicon_match: str = ""
    dns_a: list[str] = field(default_factory=list)
    dns_cname: list[str] = field(default_factory=list)


def build(
    live_hosts: list[LiveHost],
    *,
    tls_info: dict[str, TLSInfo] | None = None,
    waf_info: dict[str, WAFResult] | None = None,
    dns_records: dict[str, DNSRecord] | None = None,
) -> list[HostArchitecture]:
    """Joins every enrichment source by host/URL. All of the optional
    dicts are keyed exactly the way their own modules return them (tlsx
    by bare host, waf by full URL, dnsx by bare host) -- this function
    handles reconciling that rather than pushing the mismatch onto every
    caller."""
    tls_info = tls_info or {}
    waf_info = waf_info or {}
    dns_records = dns_records or {}

    rows: list[HostArchitecture] = []
    for host in live_hosts:
        bare_host = strip_scheme(host.url)
        tls = tls_info.get(bare_host)
        waf = waf_info.get(host.url)
        dns = dns_records.get(bare_host)

        rows.append(
            HostArchitecture(
                url=host.url,
                ip=tls.ip if tls else "",
                status_code=host.status_code,
                title=host.title or "",
                tech=host.tech,
                tls_version=tls.tls_version if tls else "",
                jarm_hash=tls.jarm_hash if tls else "",
                cert_subject=tls.subject_cn if tls else "",
                cert_issuer=tls.issuer_cn if tls else "",
                cert_misconfigurations=tls.misconfigurations() if tls else [],
                waf=waf.firewall if (waf and waf.detected) else "",
                favicon_match=host.favicon_match or "",
                dns_a=dns.a if dns else [],
                dns_cname=dns.cname if dns else [],
            )
        )
    return rows


def export_markdown(target: str, rows: list[HostArchitecture], out_path: Path) -> Path:
    lines = [
        f"# Architecture & Tech Detection — {target}",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        f"One row per live host, consolidating every tech-detection signal hunternexus gathered "
        f"(httpx tech-detect, tlsx TLS/cert probing, WAF detection, favicon fingerprinting, DNS records). "
        f"This is the infrastructure map -- for the ranked worklist of what to look at first, see the main scan report.",
        "",
        f"## Hosts ({len(rows)})",
        "",
        "| Host | IP | Status | Tech | TLS | WAF | Cert Issues | Favicon Match |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        tech = ", ".join(r.tech) if r.tech else ""
        tls = f"{r.tls_version}" if r.tls_version else ""
        cert_issues = ", ".join(r.cert_misconfigurations) if r.cert_misconfigurations else ""
        lines.append(
            f"| {r.url} | {r.ip} | {r.status_code} | {tech} | {tls} | {r.waf} | {cert_issues} | {r.favicon_match} |"
        )

    lines += ["", "## Certificate detail", ""]
    cert_rows = [r for r in rows if r.cert_subject or r.jarm_hash]
    if cert_rows:
        lines.append("| Host | Subject CN | Issuer CN | JARM Hash |")
        lines.append("|---|---|---|---|")
        for r in cert_rows:
            lines.append(f"| {r.url} | {r.cert_subject} | {r.cert_issuer} | {r.jarm_hash} |")
    else:
        lines.append("_No TLS probe data available -- run with tls_probe enabled._")

    lines += ["", "## DNS records", ""]
    dns_rows = [r for r in rows if r.dns_a or r.dns_cname]
    if dns_rows:
        lines.append("| Host | A records | CNAME |")
        lines.append("|---|---|---|")
        for r in dns_rows:
            lines.append(f"| {r.url} | {', '.join(r.dns_a)} | {', '.join(r.dns_cname)} |")
    else:
        lines.append("_No DNS record data available -- run with dns_intel enabled._")

    lines += ["", "## Tech stack frequency (across all hosts)", ""]
    tech_counts: dict[str, int] = {}
    for r in rows:
        for t in r.tech:
            tech_counts[t] = tech_counts.get(t, 0) + 1
    if tech_counts:
        lines.append("| Technology | Host count |")
        lines.append("|---|---|")
        for tech, count in sorted(tech_counts.items(), key=lambda kv: -kv[1]):
            lines.append(f"| {tech} | {count} |")
    else:
        lines.append("_No tech-detection data available._")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines))
    return out_path
