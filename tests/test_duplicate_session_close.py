from honeytrap.event_types import EventType
from honeytrap.rules.duplicate_session_close import DuplicateSessionCloseRule


def test_unique_close_events_produce_no_findings():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s2"},
    ]

    assert DuplicateSessionCloseRule().evaluate(events) == []


def test_detects_duplicate_close_events():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
    ]

    findings = DuplicateSessionCloseRule().evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-007"


def test_detects_multiple_duplicate_sessions():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s2"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s2"},
    ]

    findings = DuplicateSessionCloseRule().evaluate(events)

    assert len(findings) == 2


def test_ignores_missing_session_ids():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": ""},
    ]

    assert DuplicateSessionCloseRule().evaluate(events) == []


def test_open_events_do_not_count_as_duplicate_closes():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
    ]

    assert DuplicateSessionCloseRule().evaluate(events) == []