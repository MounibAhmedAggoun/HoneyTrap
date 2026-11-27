from honeytrap.event_types import EventType
from honeytrap.rules.abnormal_session_termination import (
    AbnormalSessionTerminationRule,
)


def make_event(event_type, timestamp, session_id="session-1"):
    return {
        "event_type": event_type,
        "session_id": session_id,
        "timestamp": timestamp,
    }


def test_two_seconds_no_finding():
    rule = AbnormalSessionTerminationRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, "2026-01-01T12:00:00"),
        make_event(EventType.CONNECTION_CLOSED, "2026-01-01T12:00:02"),
    ]

    assert rule.evaluate(events) == []


def test_exactly_one_second_no_finding():
    rule = AbnormalSessionTerminationRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, "2026-01-01T12:00:00"),
        make_event(EventType.CONNECTION_CLOSED, "2026-01-01T12:00:01"),
    ]

    assert rule.evaluate(events) == []


def test_under_one_second_detected():
    rule = AbnormalSessionTerminationRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, "2026-01-01T12:00:00"),
        make_event(EventType.CONNECTION_CLOSED, "2026-01-01T12:00:00.500000"),
    ]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-025"


def test_missing_open_event():
    rule = AbnormalSessionTerminationRule()
    events = [
        make_event(EventType.CONNECTION_CLOSED, "2026-01-01T12:00:00"),
    ]

    assert rule.evaluate(events) == []


def test_missing_close_event():
    rule = AbnormalSessionTerminationRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, "2026-01-01T12:00:00"),
    ]

    assert rule.evaluate(events) == []


def test_invalid_timestamps_ignored():
    rule = AbnormalSessionTerminationRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, "invalid"),
        make_event(EventType.CONNECTION_CLOSED, "invalid"),
    ]

    assert rule.evaluate(events) == []