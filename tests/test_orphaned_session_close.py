from honeytrap.event_types import EventType
from honeytrap.rules.orphaned_session_close import OrphanedSessionCloseRule


def test_matching_open_and_close_produce_no_findings():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
    ]

    assert OrphanedSessionCloseRule().evaluate(events) == []


def test_detects_close_without_open():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
    ]

    findings = OrphanedSessionCloseRule().evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-008"
    assert findings[0].session_id == "s1"


def test_detects_multiple_orphaned_closes():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s2"},
    ]

    findings = OrphanedSessionCloseRule().evaluate(events)

    assert len(findings) == 2


def test_ignores_close_events_without_session_id():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": ""},
    ]

    assert OrphanedSessionCloseRule().evaluate(events) == []


def test_ignores_unrelated_events():
    events = [
        {"event_type": "other_event", "session_id": "s1"},
    ]

    assert OrphanedSessionCloseRule().evaluate(events) == []