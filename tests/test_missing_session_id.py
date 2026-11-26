from honeytrap.event_types import EventType
from honeytrap.rules.missing_session_id import MissingSessionIDRule


def test_valid_events_produce_no_findings():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": "s1"},
    ]

    assert MissingSessionIDRule().evaluate(events) == []


def test_detects_missing_session_id():
    events = [
        {"event_type": EventType.CONNECTION_OPENED},
    ]

    findings = MissingSessionIDRule().evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-003"
    assert findings[0].session_id is None


def test_detects_empty_session_id():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": ""},
    ]

    findings = MissingSessionIDRule().evaluate(events)

    assert len(findings) == 1


def test_detects_multiple_invalid_events():
    events = [
        {"event_type": EventType.CONNECTION_OPENED},
        {"event_type": EventType.CONNECTION_CLOSED, "session_id": ""},
        {"event_type": EventType.CONNECTION_OPENED, "session_id": "s1"},
    ]

    findings = MissingSessionIDRule().evaluate(events)

    assert len(findings) == 2


def test_ignores_unrelated_events():
    events = [
        {"event_type": "other_event"},
        {},
    ]

    assert MissingSessionIDRule().evaluate(events) == []