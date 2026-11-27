from honeytrap.event_types import EventType
from honeytrap.rules.invalid_client_port import InvalidClientPortRule


def make_event(event_type, client_port, session_id="session-1"):
    return {
        "event_type": event_type,
        "client_port": client_port,
        "session_id": session_id,
    }


def test_valid_port():
    rule = InvalidClientPortRule()
    events = [make_event(EventType.CONNECTION_OPENED, 443)]

    assert rule.evaluate(events) == []


def test_port_zero():
    rule = InvalidClientPortRule()
    events = [make_event(EventType.CONNECTION_OPENED, 0)]

    assert len(rule.evaluate(events)) == 1


def test_port_above_range():
    rule = InvalidClientPortRule()
    events = [make_event(EventType.CONNECTION_OPENED, 65536)]

    assert len(rule.evaluate(events)) == 1


def test_string_port():
    rule = InvalidClientPortRule()
    events = [make_event(EventType.CONNECTION_OPENED, "443")]

    assert len(rule.evaluate(events)) == 1


def test_boolean_port():
    rule = InvalidClientPortRule()
    events = [make_event(EventType.CONNECTION_OPENED, True)]

    assert len(rule.evaluate(events)) == 1


def test_missing_port_is_ignored():
    rule = InvalidClientPortRule()
    events = [make_event(EventType.CONNECTION_OPENED, None)]

    assert rule.evaluate(events) == []


def test_unrelated_event_is_ignored():
    rule = InvalidClientPortRule()
    events = [make_event("unknown_event", 99999)]

    assert rule.evaluate(events) == []