import yaml

from hunternexus.config import Config
from hunternexus.modules.internet_intel import sync_uncover_provider_config


def test_syncs_configured_keys_into_fresh_file(tmp_path):
    path = tmp_path / "provider-config.yaml"
    config = Config({"api_keys": {"shodan": "SHODANKEY123", "censys": "myid:mysecret"}})

    sync_uncover_provider_config(config, path=path)

    data = yaml.safe_load(path.read_text())
    assert data["shodan"] == ["SHODANKEY123"]
    assert data["censys"] == ["myid:mysecret"]


def test_preserves_other_providers_already_in_the_file(tmp_path):
    path = tmp_path / "provider-config.yaml"
    path.write_text(yaml.dump({"fofa": ["existing-fofa-key"], "shodan": []}))
    config = Config({"api_keys": {"shodan": "SHODANKEY123"}})

    sync_uncover_provider_config(config, path=path)

    data = yaml.safe_load(path.read_text())
    assert data["fofa"] == ["existing-fofa-key"]
    assert data["shodan"] == ["SHODANKEY123"]


def test_no_key_configured_is_a_safe_noop(tmp_path):
    path = tmp_path / "provider-config.yaml"
    config = Config({})

    sync_uncover_provider_config(config, path=path)

    assert not path.exists()


def test_censys_key_without_colon_is_ignored(tmp_path):
    path = tmp_path / "provider-config.yaml"
    config = Config({"api_keys": {"censys": "not-a-valid-format"}})

    sync_uncover_provider_config(config, path=path)

    assert not path.exists()
