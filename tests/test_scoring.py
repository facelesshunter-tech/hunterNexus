from hunternexus.models import LiveHost
from hunternexus.scoring.prioritize import rank, score_host


def test_login_title_scores_higher_than_plain_200():
    login = LiveHost(url="https://vpn.example.com", status_code=200, title="SSL VPN Login Portal", tech=[])
    plain = LiveHost(url="https://blog.example.com", status_code=200, title="Our Blog", tech=[])
    score_host(login)
    score_host(plain)
    assert login.risk_score > plain.risk_score
    assert any("login" in r.lower() for r in login.risk_reasons)


def test_cve_watchlist_product_scores_highest():
    citrix = LiveHost(url="https://gateway.example.com", status_code=200, title="Citrix Gateway", tech=["Citrix"])
    score_host(citrix)
    assert citrix.risk_score >= 5.0
    assert any("CVE-2023-6548" in r for r in citrix.risk_reasons)


def test_rank_sorts_descending():
    hosts = [
        LiveHost(url="https://a.example.com", status_code=200, title="Home"),
        LiveHost(url="https://b.example.com", status_code=200, title="Admin Login"),
    ]
    ranked = rank(hosts)
    assert ranked[0].url == "https://b.example.com"
