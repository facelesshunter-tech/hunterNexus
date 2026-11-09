import json
import time
from unittest.mock import patch

from hunternexus.scoring import prioritize


def test_fresh_cache_is_used_without_network_call(tmp_path, monkeypatch):
    cache_path = tmp_path / "cisa_kev.json"
    cache_path.write_text(json.dumps(["CVE-2024-3400"]))
    monkeypatch.setattr(prioritize, "KEV_CACHE_PATH", cache_path)

    with patch("hunternexus.scoring.prioritize.get_json") as mock_get:
        ids = prioritize._load_kev_catalog(timeout=5, max_age_hours=24.0)
        mock_get.assert_not_called()

    assert ids == {"CVE-2024-3400"}


def test_stale_cache_triggers_refetch_and_is_overwritten(tmp_path, monkeypatch):
    cache_path = tmp_path / "cisa_kev.json"
    cache_path.write_text(json.dumps(["CVE-OLD-0001"]))
    old_time = time.time() - 48 * 3600
    import os
    os.utime(cache_path, (old_time, old_time))
    monkeypatch.setattr(prioritize, "KEV_CACHE_PATH", cache_path)

    with patch("hunternexus.scoring.prioritize.get_json") as mock_get:
        mock_get.return_value = {"vulnerabilities": [{"cveID": "CVE-NEW-0002"}]}
        ids = prioritize._load_kev_catalog(timeout=5, max_age_hours=24.0)
        mock_get.assert_called_once()

    assert ids == {"CVE-NEW-0002"}
    assert json.loads(cache_path.read_text()) == ["CVE-NEW-0002"]


def test_failed_fetch_falls_back_to_stale_cache(tmp_path, monkeypatch):
    cache_path = tmp_path / "cisa_kev.json"
    cache_path.write_text(json.dumps(["CVE-OLD-0001"]))
    old_time = time.time() - 48 * 3600
    import os
    os.utime(cache_path, (old_time, old_time))
    monkeypatch.setattr(prioritize, "KEV_CACHE_PATH", cache_path)

    with patch("hunternexus.scoring.prioritize.get_json") as mock_get:
        mock_get.return_value = None  # simulates www.cisa.gov being unreachable
        ids = prioritize._load_kev_catalog(timeout=5, max_age_hours=24.0)

    assert ids == {"CVE-OLD-0001"}


def test_no_cache_and_failed_fetch_returns_empty(tmp_path, monkeypatch):
    cache_path = tmp_path / "does_not_exist.json"
    monkeypatch.setattr(prioritize, "KEV_CACHE_PATH", cache_path)

    with patch("hunternexus.scoring.prioritize.get_json") as mock_get:
        mock_get.return_value = None
        ids = prioritize._load_kev_catalog(timeout=5, max_age_hours=24.0)

    assert ids == set()
