"""Regression tests for a real bug found during manual setup: Config.has()
reported blank placeholder values (the "" entries config.example.yaml
ships for every unfilled slot) as "configured", because a Python list
containing only empty strings is still a non-empty list. Fixed in
config.py's has()/api_key()/api_keys_list(); these tests pin the fix.
"""

from hunternexus.config import Config


def test_blank_string_key_is_not_configured():
    c = Config({"api_keys": {"chaos": ""}})
    assert c.has("chaos") is False
    assert c.api_key("chaos") is None


def test_all_blank_list_is_not_configured():
    c = Config({"api_keys": {"github": ["", "", ""]}})
    assert c.has("github") is False
    assert c.api_keys_list("github") == []


def test_one_real_value_in_list_is_configured():
    c = Config({"api_keys": {"github": ["ghp_real", "", ""]}})
    assert c.has("github") is True
    assert c.api_key("github") == "ghp_real"
    assert c.api_keys_list("github") == ["ghp_real"]


def test_real_single_string_key_is_configured():
    c = Config({"api_keys": {"shodan": "realkey123"}})
    assert c.has("shodan") is True
    assert c.api_key("shodan") == "realkey123"


def test_missing_source_is_not_configured():
    c = Config({"api_keys": {}})
    assert c.has("anything") is False
    assert c.api_key("anything") is None
    assert c.api_keys_list("anything") == []


def test_env_var_overrides_config_file():
    import os

    c = Config({"api_keys": {"shodan": "file-value"}})
    os.environ["HUNTERNEXUS_SHODAN_API_KEY"] = "env-value"
    try:
        assert c.api_key("shodan") == "env-value"
    finally:
        del os.environ["HUNTERNEXUS_SHODAN_API_KEY"]
