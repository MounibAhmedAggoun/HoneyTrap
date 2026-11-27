from honeytrap.event_types import EventType
from honeytrap.rules.invalid_event_data import InvalidEventDataRule


def make_event(session_id="session-1", timestamp="2026-01-01T12:00:00"):
    return {
        "event_type": EventType.CONNECTION_OPENED,
        "session_id": session_id,
        "timestamp": timestamp,
    }


def test_valid_event_data():
    rule = InvalidEventDataRule()
    assert rule.evaluate([make_event()]) == []


def test_missing_session_id():
    rule = InvalidEventDataRule()
    assert len(rule.evaluate([make_event(session_id=None)])) == 1


def test_empty_session_id():
    rule = InvalidEventDataRule()
    assert len(rule.evaluate([make_event(session_id="")])) == 1


def test_invalid_session_id_type():
    rule = InvalidEventDataRule()
    assert len(rule.evaluate([make_event(session_id=123)])) == 1


def test_missing_timestamp():
    rule = InvalidEventDataRule()
    assert len(rule.evaluate([make_event(timestamp=None)])) == 1


def test_empty_timestamp():
    rule = InvalidEventDataRule()
    assert len(rule.evaluate([make_event(timestamp="")])) == 1


def test_invalid_timestamp_type():
    rule = InvalidEventDataRule()
    assert len(rule.evaluate([make_event(timestamp=123)])) == 1


def test_close_event_valid():
    rule = InvalidEventDataRule()
    event = make_event()
    event["event_type"] = EventType.CONNECTION_CLOSED

    assert rule.evaluate([event]) == []


def test_unrelated_event_ignored():
    rule = InvalidEventDataRule()
    event = make_event()
    event["event_type"] = "UNKNOWN"

    assert rule.evaluate([event]) == []