from honeytrap.event_types import EventType
from honeytrap.rules.invalid_event_type import InvalidEventTypeRule


def test_valid_event_types_produce_no_findings():
    events = [
        {"event_type": EventType.CONNECTION_OPENED},
        {"event_type": EventType.CONNECTION_CLOSED},
    ]

    assert InvalidEventTypeRule().evaluate(events) == []


def test_detects_missing_event_type():
    events = [{"session_id": "s1"}]

    findings = InvalidEventTypeRule().evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-005"


def test_detects_unknown_event_type():
    events = [{"event_type": "unknown_event"}]

    findings = InvalidEventTypeRule().evaluate(events)

    assert len(findings) == 1


def test_detects_empty_event_type():
    events = [{"event_type": ""}]

    assert len(InvalidEventTypeRule().evaluate(events)) == 1


def test_detects_multiple_invalid_types():
    events = [
        {},
        {"event_type": "invalid_one"},
        {"event_type": "invalid_two"},
        {"event_type": EventType.CONNECTION_OPENED},
    ]

    findings = InvalidEventTypeRule().evaluate(events)

    assert len(findings) == 3


def test_handles_non_string_event_types():
    events = [
        {"event_type": None},
        {"event_type": 123},
        {"event_type": []},
    ]

    findings = InvalidEventTypeRule().evaluate(events)

    assert len(findings) == 3