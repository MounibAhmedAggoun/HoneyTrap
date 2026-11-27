from honeytrap.event_types import EventType
from honeytrap.rules.session_event_order import SessionEventOrderRule


def test_correct_event_order_produces_no_findings():
    events = [
        {
            "event_type": EventType.CONNECTION_OPENED,
            "session_id": "s1",
            "timestamp": "2026-11-27T10:00:00+00:00",
        },
        {
            "event_type": EventType.CONNECTION_CLOSED,
            "session_id": "s1",
            "timestamp": "2026-11-27T10:05:00+00:00",
        },
    ]

    assert SessionEventOrderRule().evaluate(events) == []


def test_detects_close_before_open_timestamp():
    events = [
        {
            "event_type": EventType.CONNECTION_OPENED,
            "session_id": "s1",
            "timestamp": "2026-11-27T10:05:00+00:00",
        },
        {
            "event_type": EventType.CONNECTION_CLOSED,
            "session_id": "s1",
            "timestamp": "2026-11-27T10:00:00+00:00",
        },
    ]

    findings = SessionEventOrderRule().evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-010"
    assert findings[0].session_id == "s1"


def test_equal_timestamps_are_valid():
    events = [
        {
            "event_type": EventType.CONNECTION_OPENED,
            "session_id": "s1",
            "timestamp": "2026-11-27T10:00:00+00:00",
        },
        {
            "event_type": EventType.CONNECTION_CLOSED,
            "session_id": "s1",
            "timestamp": "2026-11-27T10:00:00+00:00",
        },
    ]

    assert SessionEventOrderRule().evaluate(events) == []


def test_ignores_missing_timestamps():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
    ]

    assert SessionEventOrderRule().evaluate(events) == []


def test_ignores_invalid_timestamps():
    events = [
        {
            "event_type": EventType.CONNECTION_OPENED,
            "session_id": "s1",
            "timestamp": "invalid",
        },
        {
            "event_type": EventType.CONNECTION_CLOSED,
            "session_id": "s1",
            "timestamp": "invalid",
        },
    ]

    assert SessionEventOrderRule().evaluate(events) == []