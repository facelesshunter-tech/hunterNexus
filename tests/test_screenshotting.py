"""Regression test for a real bug found during manual verification:
gowitness_scan's JSONL parser looked for the screenshot path under
"filename" or "screenshot" keys, but gowitness v3 actually writes it
under "file_name" (and leaves "screenshot" as an empty string). Fixed by
reading "file_name" and joining it onto the screenshot directory path.
This test uses a real JSONL line captured from an actual gowitness run
against https://one.one.one.one during verification, trimmed of fields
screenshotting.py doesn't use.
"""

import json
from pathlib import Path

from hunternexus.config import Config
from hunternexus.modules.screenshotting import gowitness_scan

REAL_GOWITNESS_RECORD = {
    "id": 0,
    "url": "https://one.one.one.one:443",
    "final_url": "https://one.one.one.one/",
    "response_code": 200,
    "title": "1.1.1.1 — The free app that makes your Internet faster.",
    "screenshot": "",
    "file_name": "https---one.one.one.one-443.jpeg",
    "failed": False,
    "failed_reason": "",
}


def test_gowitness_jsonl_parsing_uses_file_name_field(tmp_path, monkeypatch):
    output_dir = tmp_path / "out"
    screenshot_dir = output_dir / "screenshots"
    screenshot_dir.mkdir(parents=True)
    jsonl_path = output_dir / "gowitness.jsonl"
    jsonl_path.write_text(json.dumps(REAL_GOWITNESS_RECORD) + "\n")

    # Pretend the actual screenshot file exists, same as a real scan would produce.
    (screenshot_dir / "https---one.one.one.one-443.jpeg").write_bytes(b"fake-jpeg-bytes")

    # Stub out the actual subprocess call -- we're testing the JSONL parser,
    # not gowitness itself (that's covered by the live smoke test done
    # manually during verification, not part of the automated suite since
    # it needs network access and a real browser).
    from hunternexus.modules import screenshotting as mod
    from hunternexus.utils.subprocess_runner import RunResult

    class FakeConfig(Config):
        def tool_path(self, tool):
            return "/bin/true" if tool == "gowitness" else None

    monkeypatch.setattr(mod, "run", lambda *a, **k: RunResult(returncode=0, stdout="", stderr=""))

    results = gowitness_scan(FakeConfig({}), ["https://one.one.one.one"], output_dir)

    assert len(results) == 1
    r = results[0]
    assert r.title == "1.1.1.1 — The free app that makes your Internet faster."
    assert r.screenshot_path == str(screenshot_dir / "https---one.one.one.one-443.jpeg")
    assert Path(r.screenshot_path).is_file()
