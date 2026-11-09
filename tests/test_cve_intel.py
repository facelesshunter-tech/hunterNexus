from hunternexus.models import LiveHost
from hunternexus.scoring import prioritize


def test_scoring_works_without_intel_refresh():
    """Baseline behavior must be unaffected if refresh_cve_intel() is
    never called -- EPSS/KEV is an enhancement, not a requirement."""
    prioritize._intel_loaded = False
    prioritize._epss_cache.clear()
    prioritize._kev_cache.clear()

    host = LiveHost(url="https://x.example", status_code=200, title="Citrix Login", tech=["Citrix"])
    prioritize.score_host(host)
    assert host.risk_score == 5.0 + 2.0  # watchlist match + login-title match
    assert not any("EPSS" in r or "KEV" in r for r in host.risk_reasons)


def test_cve_intel_bonus_applies_when_cached():
    """Once intel is (simulated as) loaded, matching CVEs should add the
    documented bonuses and reasons."""
    prioritize._intel_loaded = True
    prioritize._kev_cache = {"CVE-2023-6548"}
    prioritize._epss_cache = {"CVE-2023-6548": 0.95}
    try:
        host = LiveHost(url="https://x.example", status_code=200, title="Citrix Login", tech=["Citrix"])
        prioritize.score_host(host)
        assert host.risk_score == 5.0 + 2.0 + 3.0 + 2.0  # watchlist + login + KEV + EPSS
        assert any("Known Exploited Vulnerabilities" in r for r in host.risk_reasons)
        assert any("EPSS exploitation-probability" in r for r in host.risk_reasons)
    finally:
        prioritize._intel_loaded = False
        prioritize._kev_cache = set()
        prioritize._epss_cache = {}
