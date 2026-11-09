from hunternexus.modules.parameter_discovery import _describe_arjun_failure


def test_known_crash_signature_gets_clear_message():
    stderr = (
        "Traceback (most recent call last):\n"
        "  File \"/x/arjun\", line 6, in <module>\n"
        "    sys.exit(main())\n"
        "AttributeError: 'dict' object has no attribute 'status_code'\n"
    )
    msg = _describe_arjun_failure(stderr)
    assert "known upstream bug" in msg
    assert "Not a hunternexus issue" in msg


def test_unrecognized_traceback_still_labeled_as_internal_crash():
    stderr = "Traceback (most recent call last):\n  File \"x.py\", line 1\nValueError: something else\n"
    msg = _describe_arjun_failure(stderr)
    assert "unrecognized traceback" in msg
    assert "ValueError: something else" in msg


def test_plain_stderr_passed_through():
    msg = _describe_arjun_failure("connection refused")
    assert msg == "connection refused"
