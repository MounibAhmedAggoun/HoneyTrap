from honeytrap.rules.invalid_timestamp import InvalidTimestampRule


def test_valid_timestamps_produce_no_findings():
    events = [
        {"timestamp": "2026-11-26T07:30:00+00:00"},
        {"timestamp": "2026-11-26T07:30:00"},
    ]

    assert InvalidTimestampRule().evaluate(events) == []


def test_detects_missing_timestamp():
    events = [{"event_type": "connection_opened"}]

    findings = InvalidTimestampRule().evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-004"


def test_detects_empty_timestamp():
    events = [{"timestamp": ""}]

    findings = InvalidTimestampRule().evaluate(events)

    assert len(findings) == 1


def test_detects_malformed_timestamp():
    events = [{"timestamp": "not-a-date"}]

    findings = InvalidTimestampRule().evaluate(events)

    assert len(findings) == 1
    assert "invalid timestamp" in findings[0].message


def test_detects_multiple_invalid_timestamps():
    events = [
        {},
        {"timestamp": ""},
        {"timestamp": "broken"},
        {"timestamp": "2026-11-26T07:30:00"},
    ]

    findings = InvalidTimestampRule().evaluate(events)

    assert len(findings) == 3


def test_handles_non_string_timestamps():
    events = [
        {"timestamp": 12345},
        {"timestamp": None},
        {"timestamp": []},
    ]

    findings = InvalidTimestampRule().evaluate(events)

    assert len(findings) == 3