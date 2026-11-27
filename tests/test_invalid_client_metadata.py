from honeytrap.event_types import EventType
from honeytrap.rules.invalid_client_metadata import (
    InvalidClientMetadataRule,
)


def make_event(client_ip="192.168.1.10", client_port=5001):
    return {
        "event_type": EventType.CONNECTION_OPENED,
        "client_ip": client_ip,
        "client_port": client_port,
        "session_id": "session-1",
        "timestamp": "2026-01-01T12:00:00",
    }


def test_valid_metadata():
    rule = InvalidClientMetadataRule()
    assert rule.evaluate([make_event()]) == []


def test_missing_client_ip():
    rule = InvalidClientMetadataRule()
    assert len(rule.evaluate([make_event(client_ip=None)])) == 1


def test_empty_client_ip():
    rule = InvalidClientMetadataRule()
    assert len(rule.evaluate([make_event(client_ip="")])) == 1


def test_missing_client_port():
    rule = InvalidClientMetadataRule()
    assert len(rule.evaluate([make_event(client_port=None)])) == 1


def test_port_below_range():
    rule = InvalidClientMetadataRule()
    assert len(rule.evaluate([make_event(client_port=0)])) == 1


def test_port_above_range():
    rule = InvalidClientMetadataRule()
    assert len(rule.evaluate([make_event(client_port=65536)])) == 1


def test_invalid_ip_type():
    rule = InvalidClientMetadataRule()
    assert len(rule.evaluate([make_event(client_ip=123)])) == 1


def test_invalid_port_type():
    rule = InvalidClientMetadataRule()
    assert len(rule.evaluate([make_event(client_port="5001")])) == 1


def test_boolean_port_rejected():
    rule = InvalidClientMetadataRule()
    assert len(rule.evaluate([make_event(client_port=True)])) == 1


def test_close_events_ignored():
    rule = InvalidClientMetadataRule()
    event = make_event(client_ip=None, client_port=None)
    event["event_type"] = EventType.CONNECTION_CLOSED

    assert rule.evaluate([event]) == []