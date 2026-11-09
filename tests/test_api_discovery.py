from unittest.mock import patch

from hunternexus.config import Config
from hunternexus.modules import api_discovery
from hunternexus.utils.subprocess_runner import RunResult

# Real kr output, captured live against httpbin.org/get (a genuine positive
# match) -- the field names here are what exposed the original bug: the
# module used to filter on/parse a flat {"url","status_code","content_length"}
# shape that never once matched a real hit record, silently discarding
# every genuine finding.
REAL_INFO_LINE = '{"level":"info","delay":"0s","full-scan":true,"target":"https://httpbin.org","total-routes":3,"message":"scan options"}'
REAL_HIT_LINE = '{"method":"GET","target":"https://httpbin.org","path":"/get","responses":[{"uri":"","sc":200,"len":307}],"time":"2026-11-09T07:59:35+01:00"}'
REAL_SUMMARY_LINE = '{"level":"info","results":1,"duration":4481.687972,"message":"scan complete"}'


def test_real_positive_hit_is_parsed_correctly():
    stdout = "\n".join([REAL_INFO_LINE, REAL_HIT_LINE, REAL_SUMMARY_LINE])
    with patch("hunternexus.modules.api_discovery.run") as mock_run:
        mock_run.return_value = RunResult(returncode=0, stdout=stdout, stderr="")
        config = Config({})
        hits = api_discovery.scan(config, "https://httpbin.org", custom_kite_file="/tmp/fake.kite")

    assert len(hits) == 1
    hit = hits[0]
    assert hit.method == "GET"
    assert hit.target == "https://httpbin.org"
    assert hit.path == "/get"
    assert hit.status_code == 200
    assert hit.content_length == 307
    assert hit.url == "https://httpbin.org/get"


def test_info_and_summary_lines_are_not_treated_as_hits():
    stdout = "\n".join([REAL_INFO_LINE, REAL_SUMMARY_LINE])
    with patch("hunternexus.modules.api_discovery.run") as mock_run:
        mock_run.return_value = RunResult(returncode=0, stdout=stdout, stderr="")
        config = Config({})
        hits = api_discovery.scan(config, "https://httpbin.org", custom_kite_file="/tmp/fake.kite")
    assert hits == []
