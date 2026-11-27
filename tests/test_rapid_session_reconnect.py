from honeytrap.event_types import EventType
from honeytrap.rules.rapid_session_reconnect import (
    RapidSessionReconnectRule,
)


def make_event(event_type, timestamp, client_ip="192.168.1.10"):
    return {
        "event_type": event_type,
        "timestamp": timestamp,
        "client_ip": client_ip,
    }


def make_pair(seconds, client_ip="192.168.1.10"):
    return [
        make_event(EventType.CONNECTION_CLOSED, "2026-01-01T12:00:00"),
        make_event(
            EventType.CONNECTION_OPENED,
            f"2026-01-01T12:00:{seconds:02d}",
            client_ip,
        ),
    ]


def test_reconnect_after_two_seconds():
    rule = RapidSessionReconnectRule()
    assert len(rule.evaluate(make_pair(2))) == 1


def test_reconnect_after_five_seconds():
    rule = RapidSessionReconnectRule()
    assert len(rule.evaluate(make_pair(5))) == 1


def test_reconnect_after_six_seconds():
    rule = RapidSessionReconnectRule()
    assert rule.evaluate(make_pair(6)) == []


def test_different_ips():
    rule = RapidSessionReconnectRule()
    events = [
        make_event(EventType.CONNECTION_CLOSED, "2026-01-01T12:00:00", "192.168.1.10"),
        make_event(EventType.CONNECTION_OPENED, "2026-01-01T12:00:02", "192.168.1.11"),
    ]

    assert rule.evaluate(events) == []


def test_invalid_timestamps_ignored():
    rule = RapidSessionReconnectRule()
    events = [
        make_event(EventType.CONNECTION_CLOSED, "invalid"),
        make_event(EventType.CONNECTION_OPENED, "invalid"),
    ]

    assert rule.evaluate(events) == []