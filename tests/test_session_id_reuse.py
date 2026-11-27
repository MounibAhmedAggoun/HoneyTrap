from honeytrap.event_types import EventType
from honeytrap.rules.session_id_reuse import SessionIDReuseRule


def make_event(event_type, session_id="session-1"):
    return {
        "event_type": event_type,
        "session_id": session_id,
    }


def test_single_session_id_is_not_reuse():
    rule = SessionIDReuseRule()
    events = [
        make_event(EventType.CONNECTION_OPENED),
        make_event(EventType.CONNECTION_CLOSED),
    ]

    assert rule.evaluate(events) == []


def test_reused_session_id():
    rule = SessionIDReuseRule()
    events = [
        make_event(EventType.CONNECTION_OPENED),
        make_event(EventType.CONNECTION_CLOSED),
        make_event(EventType.CONNECTION_OPENED),
        make_event(EventType.CONNECTION_CLOSED),
    ]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-012"
    assert findings[0].session_id == "session-1"


def test_multiple_session_ids():
    rule = SessionIDReuseRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, "session-1"),
        make_event(EventType.CONNECTION_CLOSED, "session-1"),
        make_event(EventType.CONNECTION_OPENED, "session-2"),
        make_event(EventType.CONNECTION_CLOSED, "session-2"),
        make_event(EventType.CONNECTION_OPENED, "session-1"),
    ]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert findings[0].session_id == "session-1"


def test_missing_session_ids_are_ignored():
    rule = SessionIDReuseRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, None),
        make_event(EventType.CONNECTION_OPENED, ""),
    ]

    assert rule.evaluate(events) == []