"""Certificate-based ASN/cloud-range pivoting and CT-log cert pivoting.

Scans IP ranges for TLS certificates and pulls hostnames out of the
CN/SAN fields (the Caduceus technique), plus pulling from
kaeferjaeger.gay's pre-scanned, weekly-updated cloud-provider cert
datasets (so you don't have to re-scan all of AWS/Azure/GCP/Oracle/DO
yourself), and crt.sh for certificate-transparency-log pivoting (the
passive, no-scanning equivalent of the same idea).
"""

from __future__ import annotations

import concurrent.futures
import gzip
import ipaddress
import logging
import socket
import ssl
from dataclasses import dataclass, field

from hunternexus.utils.http import get_json
from hunternexus.utils.dedupe import dedupe_strings

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None  # type: ignore

logger = logging.getLogger("hunternexus.cert_pivot")

CRTSH_BASE = "https://crt.sh"

KAEFERJAEGER_INDEX = {
    "aws": "https://kaeferjaeger.gay/sni-ip-ranges/amazon/ipv4_merged_sni.txt",
    "azure": "https://kaeferjaeger.gay/sni-ip-ranges/microsoft/ipv4_merged_sni.txt",
    "gcp": "https://kaeferjaeger.gay/sni-ip-ranges/google/ipv4_merged_sni.txt",
    "oracle": "https://kaeferjaeger.gay/sni-ip-ranges/oracle/ipv4_merged_sni.txt",
    "digitalocean": "https://kaeferjaeger.gay/sni-ip-ranges/digitalocean/ipv4_merged_sni.txt",
}


@dataclass
class CertHit:
    ip: str
    port: int
    common_name: str = ""
    sans: list[str] = field(default_factory=list)

    def hostnames(self) -> list[str]:
        return dedupe_strings([self.common_name] + self.sans)


def _grab_cert(ip: str, port: int, timeout: float) -> CertHit | None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, socket.timeout):
        return None
    if not der:
        return None
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.x509.oid import NameOID

        cert = x509.load_der_x509_certificate(der, default_backend())
        cn = ""
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        except IndexError:
            pass
        sans: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        return CertHit(ip=ip, port=port, common_name=cn, sans=sans)
    except Exception as e:  # pragma: no cover
        logger.debug("failed to parse cert from %s:%s: %s", ip, port, e)
        return None


def scan_cidrs(
    cidrs: list[str],
    *,
    ports: list[int] | None = None,
    timeout: float = 2.0,
    max_workers: int = 50,
    max_hosts: int = 65536,
) -> list[CertHit]:
    """The Caduceus technique: connect to every host in a set of CIDRs and
    pull TLS cert CN/SAN values. This is the active, scan-it-yourself
    counterpart to the kaeferjaeger.gay pre-scanned dataset below -- use it
    for ranges kaeferjaeger doesn't cover, or to re-verify freshness."""
    ports = ports or [443]
    targets: list[str] = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning("skipping invalid CIDR %r", cidr)
            continue
        for ip in net.hosts():
            targets.append(str(ip))
            if len(targets) >= max_hosts:
                logger.warning("max_hosts=%d reached, truncating scan scope", max_hosts)
                break
        if len(targets) >= max_hosts:
            break

    hits: list[CertHit] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_grab_cert, ip, port, timeout): (ip, port)
            for ip in targets
            for port in ports
        }
        for fut in concurrent.futures.as_completed(futures):
            result = fut.result()
            if result is not None and result.hostnames():
                hits.append(result)
    return hits


def kaeferjaeger_lookup(provider: str, keyword: str, *, cache_dir: str | None = None) -> list[str]:
    """Pull kaeferjaeger.gay's weekly pre-scanned cert SNI dataset for a
    cloud provider and grep it for a keyword -- avoids re-scanning all of
    AWS/Azure/GCP yourself."""
    if requests is None:
        logger.warning("requests not installed; cannot fetch kaeferjaeger dataset")
        return []
    url = KAEFERJAEGER_INDEX.get(provider.lower())
    if not url:
        logger.warning("unknown provider %r for kaeferjaeger -- known: %s", provider, list(KAEFERJAEGER_INDEX))
        return []
    try:
        resp = requests.get(url, timeout=120, stream=True)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.warning("failed to fetch kaeferjaeger dataset for %s: %s", provider, e)
        return []

    keyword_lower = keyword.lower()
    hits: list[str] = []
    content_type = resp.headers.get("Content-Type", "")
    raw = resp.content
    if url.endswith(".gz") or "gzip" in content_type:
        try:
            raw = gzip.decompress(raw)
        except OSError:
            pass
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        if keyword_lower in line.lower():
            hits.append(line.strip())
    return hits


def crtsh_lookup(domain: str) -> list[str]:
    """Certificate Transparency log lookup via crt.sh's public JSON
    endpoint -- the passive counterpart to active cert scanning. Returns
    every distinct hostname ever logged in a cert for this domain
    (including historical and wildcard-expanded names)."""
    data = get_json(f"{CRTSH_BASE}/", params={"q": f"%.{domain}", "output": "json"}, timeout=60)
    if not data:
        return []
    names: list[str] = []
    for entry in data:
        value = entry.get("name_value", "")
        for name in value.split("\n"):
            name = name.strip().lstrip("*.")
            if name:
                names.append(name)
    return dedupe_strings(names)
