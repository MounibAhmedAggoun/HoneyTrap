from honeytrap.event_types import EventType
from honeytrap.rules.excessive_session_event_count import (
    ExcessiveSessionEventCountRule,
)


def make_event(event_type, session_id="session-1"):
    return {
        "event_type": event_type,
        "session_id": session_id,
    }


def test_normal_session_event_count():
    rule = ExcessiveSessionEventCountRule()
    events = [
        make_event(EventType.CONNECTION_OPENED),
        make_event(EventType.CONNECTION_CLOSED),
    ]

    assert rule.evaluate(events) == []


def test_event_count_at_threshold():
    rule = ExcessiveSessionEventCountRule()
    events = [
        make_event(EventType.CONNECTION_OPENED),
        make_event(EventType.CONNECTION_CLOSED),
        make_event(EventType.CONNECTION_OPENED),
        make_event(EventType.CONNECTION_CLOSED),
    ]

    assert rule.evaluate(events) == []


def test_excessive_event_count():
    rule = ExcessiveSessionEventCountRule()
    events = [
        make_event(EventType.CONNECTION_OPENED),
        make_event(EventType.CONNECTION_CLOSED),
        make_event(EventType.CONNECTION_OPENED),
        make_event(EventType.CONNECTION_CLOSED),
        make_event(EventType.CONNECTION_OPENED),
    ]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-011"
    assert findings[0].session_id == "session-1"


def test_multiple_sessions():
    rule = ExcessiveSessionEventCountRule()
    events = [
        *[make_event(EventType.CONNECTION_OPENED, "session-1") for _ in range(5)],
        *[make_event(EventType.CONNECTION_OPENED, "session-2") for _ in range(2)],
    ]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert findings[0].session_id == "session-1"


def test_events_without_session_id_are_ignored():
    rule = ExcessiveSessionEventCountRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, None)
        for _ in range(6)
    ]

    assert rule.evaluate(events) == []


def test_unrelated_event_types_are_ignored():
    rule = ExcessiveSessionEventCountRule()
    events = [
        make_event("unknown_event")
        for _ in range(6)
    ]

    assert rule.evaluate(events) == []