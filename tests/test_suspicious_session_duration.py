from honeytrap.event_types import EventType
from honeytrap.rules.suspicious_session_duration import (
    SuspiciousSessionDurationRule,
)


def make_event(event_type, timestamp, session_id="session-1"):
    return {
        "event_type": event_type,
        "session_id": session_id,
        "timestamp": timestamp,
    }


def test_normal_duration():
    rule = SuspiciousSessionDurationRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, "2026-01-01T00:00:00"),
        make_event(EventType.CONNECTION_CLOSED, "2026-01-01T01:00:00"),
    ]

    assert rule.evaluate(events) == []


def test_exactly_24_hours():
    rule = SuspiciousSessionDurationRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, "2026-01-01T00:00:00"),
        make_event(EventType.CONNECTION_CLOSED, "2026-01-02T00:00:00"),
    ]

    assert rule.evaluate(events) == []


def test_over_24_hours():
    rule = SuspiciousSessionDurationRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, "2026-01-01T00:00:00"),
        make_event(EventType.CONNECTION_CLOSED, "2026-01-02T00:00:01"),
    ]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-019"


def test_missing_open_event():
    rule = SuspiciousSessionDurationRule()
    events = [
        make_event(EventType.CONNECTION_CLOSED, "2026-01-03T00:00:00"),
    ]

    assert rule.evaluate(events) == []


def test_missing_close_event():
    rule = SuspiciousSessionDurationRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, "2026-01-01T00:00:00"),
    ]

    assert rule.evaluate(events) == []


def test_invalid_timestamps_ignored():
    rule = SuspiciousSessionDurationRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, "invalid"),
        make_event(EventType.CONNECTION_CLOSED, "also-invalid"),
    ]

    assert rule.evaluate(events) == []