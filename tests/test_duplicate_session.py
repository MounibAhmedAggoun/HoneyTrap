from honeytrap.event_types import EventType
from honeytrap.rules.duplicate_session import DuplicateSessionRule


def test_no_duplicates():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s2"},
    ]

    assert DuplicateSessionRule().evaluate(events) == []


def test_detects_duplicate_open_events():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
    ]

    findings = DuplicateSessionRule().evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-002"
    assert findings[0].session_id == "s1"


def test_detects_multiple_duplicate_sessions():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s2"},
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s2"},
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
    ]

    findings = DuplicateSessionRule().evaluate(events)

    assert len(findings) == 2
    assert [finding.session_id for finding in findings] == ["s1", "s2"]


def test_ignores_events_without_session_id():
    events = [
        {"event_type": EventType.CONNECTION_OPENED},
        {"event_type": EventType.CONNECTION_OPENED},
    ]

    assert DuplicateSessionRule().evaluate(events) == []


def test_closed_events_do_not_count_as_duplicates():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
    ]

    assert DuplicateSessionRule().evaluate(events) == []