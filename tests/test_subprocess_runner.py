"""Regression test for a real bug found while testing web_crawl.py against
a slow-responding target: subprocess.TimeoutExpired.stdout/.stderr are
always raw bytes in Python, even when text=True was passed to
subprocess.run() -- unlike the normal successful-completion path, which
decodes properly. The original timeout handler returned those bytes
objects as-is, so every caller downstream that called .splitlines() on a
timed-out result got a list of bytes objects instead of str, which then
printed/compared as `b'...'`-repr strings anywhere they flowed into
string-based logic (dedupe_strings, report rendering, etc.) -- silent
and easy to miss as a bug, since it only shows up when a tool times out
with partial output already captured, not on clean success or a
no-output failure.
"""

from hunternexus.utils.subprocess_runner import run


def test_timeout_with_partial_output_is_decoded_to_str():
    # `yes` floods stdout forever; a 1s timeout guarantees partial output
    # was captured at the moment of the timeout, reproducing the exact
    # condition that exposed the bug (a tool that timed out mid-stream
    # with some real output already buffered).
    result = run(["yes", "hello"], timeout=1)
    assert result.returncode == 124
    assert isinstance(result.stdout, str)
    assert not result.stdout.startswith("b'")
    lines = result.stdout.splitlines()
    assert lines  # some partial output should have been captured
    assert all(isinstance(line, str) for line in lines)
    assert lines[0] == "hello"


def test_timeout_with_no_output_does_not_crash():
    result = run(["sleep", "5"], timeout=1)
    assert result.returncode == 124
    assert result.stdout == ""
    assert isinstance(result.stdout, str)
