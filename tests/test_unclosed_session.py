from honeytrap.event_types import EventType
from honeytrap.rules.unclosed_session import UnclosedSessionRule


def test_no_findings_for_closed_session():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
    ]

    assert UnclosedSessionRule().evaluate(events) == []


def test_detects_unclosed_session():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
    ]

    findings = UnclosedSessionRule().evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-001"
    assert findings[0].session_id == "s1"


def test_ignores_events_without_session_id():
    events = [
        {"event_type": EventType.CONNECTION_OPENED},
    ]

    assert UnclosedSessionRule().evaluate(events) == []


def test_detects_multiple_unclosed_sessions():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s2"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s2"},
    ]

    findings = UnclosedSessionRule().evaluate(events)

    assert len(findings) == 1
    assert findings[0].session_id == "s1"


def test_rule_does_not_duplicate_findings():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
    ]

    findings = UnclosedSessionRule().evaluate(events)

    assert len(findings) == 1