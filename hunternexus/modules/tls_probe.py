"""Per-host active TLS/certificate probing (tlsx).

Distinct from cert_pivot.py's scan_cidrs() (which sweeps an IP *range*
looking for new hostnames to discover) -- this operates on a *known*
hostname list and asks "what does this specific host's live certificate
actually look like right now": TLS version, cipher, JARM fingerprint,
and critically the misconfiguration flags (expired/self-signed/
mismatched/revoked/untrusted certs) that are genuine, reportable findings
in their own right, not just recon metadata.

This is one of the two sources (alongside live_validation.py's httpx
tech-detect) that feeds reporting/architecture.py's per-host tech
breakdown.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from hunternexus.config import Config
from hunternexus.utils.subprocess_runner import run

logger = logging.getLogger("hunternexus.tls_probe")


@dataclass
class TLSInfo:
    host: str
    ip: str = ""
    port: str = "443"
    probe_status: bool = False
    tls_version: str = ""
    cipher: str = ""
    subject_cn: str = ""
    subject_org: list[str] = field(default_factory=list)
    subject_an: list[str] = field(default_factory=list)
    issuer_cn: str = ""
    jarm_hash: str = ""
    not_before: str = ""
    not_after: str = ""
    wildcard_certificate: bool = False
    expired: bool = False
    self_signed: bool = False
    mismatched: bool = False
    revoked: bool = False
    untrusted: bool = False

    def misconfigurations(self) -> list[str]:
        flags = []
        if self.expired:
            flags.append("expired certificate")
        if self.self_signed:
            flags.append("self-signed certificate")
        if self.mismatched:
            flags.append("hostname/certificate mismatch")
        if self.revoked:
            flags.append("revoked certificate")
        if self.untrusted:
            flags.append("untrusted certificate chain")
        return flags


def probe(config: Config, hosts: list[str], *, timeout: int = 900) -> dict[str, TLSInfo]:
    path = config.tool_path("tlsx")
    if not path:
        logger.warning("tlsx not found on PATH -- install with: go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest")
        return {}

    argv = [path, "-silent", "-json", "-jarm", "-ex", "-ss", "-mm", "-re", "-un"]
    result = run(argv, stdin_text="\n".join(hosts), timeout=timeout)
    if not result.ok and not result.stdout:
        logger.warning("tlsx exited %s: %s", result.returncode, result.stderr.strip()[:300])
        return {}

    out: dict[str, TLSInfo] = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = record.get("host", "")
        if not host:
            continue
        out[host] = TLSInfo(
            host=host,
            ip=record.get("ip", ""),
            port=record.get("port", "443"),
            probe_status=record.get("probe_status", False),
            tls_version=record.get("tls_version", ""),
            cipher=record.get("cipher", ""),
            subject_cn=record.get("subject_cn", ""),
            subject_org=record.get("subject_org", []) or [],
            subject_an=record.get("subject_an", []) or [],
            issuer_cn=record.get("issuer_cn", ""),
            jarm_hash=record.get("jarm_hash", ""),
            not_before=record.get("not_before", ""),
            not_after=record.get("not_after", ""),
            wildcard_certificate=record.get("wildcard_certificate", False),
            expired=record.get("expired", False),
            self_signed=record.get("self_signed", False),
            mismatched=record.get("mismatched", False),
            revoked=record.get("revoked", False),
            untrusted=record.get("untrusted", False),
        )
    return out
