from honeytrap.event_types import EventType
from honeytrap.rules.invalid_session_duration import InvalidSessionDurationRule


def test_valid_durations_produce_no_findings():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED, "details": {"duration": 10.5}},
        {"event_type": EventType.CONNECTION_CLOSED, "details": {"duration": 0}},
    ]

    assert InvalidSessionDurationRule().evaluate(events) == []


def test_detects_negative_duration():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED, "details": {"duration": -5}},
    ]

    findings = InvalidSessionDurationRule().evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-009"


def test_detects_missing_duration():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED, "details": {}},
    ]

    assert len(InvalidSessionDurationRule().evaluate(events)) == 1


def test_detects_non_numeric_duration():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED, "details": {"duration": "10"}},
    ]

    assert len(InvalidSessionDurationRule().evaluate(events)) == 1


def test_ignores_non_closed_events():
    events = [
        {"event_type": EventType.CONNECTION_OPENED, "details": {"duration": -5}},
    ]

    assert InvalidSessionDurationRule().evaluate(events) == []


def test_handles_malformed_details():
    events = [
        {"event_type": EventType.CONNECTION_CLOSED},
        {"event_type": EventType.CONNECTION_CLOSED, "details": None},
        {"event_type": EventType.CONNECTION_CLOSED, "details": []},
    ]

    findings = InvalidSessionDurationRule().evaluate(events)

    assert len(findings) == 3