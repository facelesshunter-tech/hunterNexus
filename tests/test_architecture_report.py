from hunternexus.models import LiveHost
from hunternexus.modules.tls_probe import TLSInfo
from hunternexus.modules.waf_detect import WAFResult
from hunternexus.modules.dns_intel import DNSRecord
from hunternexus.reporting import architecture


def test_build_joins_all_sources_by_host():
    hosts = [LiveHost(url="https://vpn.example.com", status_code=200, title="SSL VPN", tech=["nginx"])]
    tls = {"vpn.example.com": TLSInfo(host="vpn.example.com", ip="10.0.0.1", tls_version="1.3", expired=True)}
    waf = {"https://vpn.example.com": WAFResult(url="https://vpn.example.com", detected=True, firewall="Cloudflare")}
    dns = {"vpn.example.com": DNSRecord(host="vpn.example.com", a=["10.0.0.1"], cname=["edge.example.net"])}

    rows = architecture.build(hosts, tls_info=tls, waf_info=waf, dns_records=dns)

    assert len(rows) == 1
    row = rows[0]
    assert row.ip == "10.0.0.1"
    assert row.tls_version == "1.3"
    assert row.cert_misconfigurations == ["expired certificate"]
    assert row.waf == "Cloudflare"
    assert row.dns_a == ["10.0.0.1"]
    assert row.dns_cname == ["edge.example.net"]


def test_build_tolerates_missing_enrichment():
    hosts = [LiveHost(url="https://bare.example.com", status_code=200, title="Bare host", tech=[])]
    rows = architecture.build(hosts)
    assert rows[0].ip == ""
    assert rows[0].waf == ""
    assert rows[0].dns_a == []


def test_export_markdown_writes_readable_report(tmp_path):
    hosts = [LiveHost(url="https://vpn.example.com", status_code=200, title="SSL VPN", tech=["nginx", "OpenVPN"])]
    rows = architecture.build(hosts)
    out = architecture.export_markdown("example.com", rows, tmp_path / "architecture.md")

    text = out.read_text()
    assert "Architecture & Tech Detection — example.com" in text
    assert "vpn.example.com" not in text or "https://vpn.example.com" in text
    assert "nginx" in text
    assert "OpenVPN" in text
