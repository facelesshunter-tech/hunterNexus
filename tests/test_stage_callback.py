from pathlib import Path

from hunternexus.config import Config
from hunternexus.pipeline import Pipeline, PipelineOptions
from hunternexus.ui import estimate_stage_count
from hunternexus.modules import subdomain_passive, live_validation


def test_on_stage_is_called_for_start_and_done(tmp_path, monkeypatch):
    events = []

    def fake_passive_enumerate(config, domain, **kwargs):
        return {}

    def fake_probe(config, hosts, **kwargs):
        return []

    monkeypatch.setattr(subdomain_passive, "passive_enumerate", fake_passive_enumerate)
    monkeypatch.setattr(live_validation, "probe", fake_probe)

    options = PipelineOptions(
        use_subfinder=False, use_amass=False, use_bbot=False, use_crtsh=False, use_assetfinder=False,
        use_dns_intel=False, use_tls_probe=False, use_cve_intel=False,
        output_dir=tmp_path,
    )
    pipeline = Pipeline(Config({}), options, on_stage=lambda label, status, detail: events.append((label, status)))
    try:
        pipeline.run("example.com")
    finally:
        pipeline.close()

    labels_started = [label for label, status in events if status == "start"]
    labels_done = [label for label, status in events if status == "done"]
    assert "Passive subdomain discovery" in labels_started
    assert "Passive subdomain discovery" in labels_done
    # every "start" must have a matching "done", in order
    assert labels_started == labels_done


def test_default_on_stage_is_a_safe_noop(tmp_path, monkeypatch):
    def fake_passive_enumerate(config, domain, **kwargs):
        return {}

    def fake_probe(config, hosts, **kwargs):
        return []

    monkeypatch.setattr(subdomain_passive, "passive_enumerate", fake_passive_enumerate)
    monkeypatch.setattr(live_validation, "probe", fake_probe)

    options = PipelineOptions(
        use_subfinder=False, use_amass=False, use_bbot=False, use_crtsh=False, use_assetfinder=False,
        use_dns_intel=False, use_tls_probe=False, use_cve_intel=False,
        output_dir=tmp_path,
    )
    # No on_stage passed at all -- must not raise.
    pipeline = Pipeline(Config({}), options)
    try:
        pipeline.run("example.com")
    finally:
        pipeline.close()


def test_estimate_stage_count_matches_quick_preset_defaults():
    options = PipelineOptions(output_dir=Path("/tmp"))
    # passive(1) + dns_intel(1) + live_validation(1) + tls_probe(1) +
    # cve_intel(1) + scoring(1) + architecture+export(2) = 8
    assert estimate_stage_count(options) == 8


def test_estimate_stage_count_increases_with_more_stages_enabled():
    base = PipelineOptions(output_dir=Path("/tmp"))
    more = PipelineOptions(output_dir=Path("/tmp"), use_github=True, use_screenshots=True, use_web_crawl=True)
    assert estimate_stage_count(more) == estimate_stage_count(base) + 3
