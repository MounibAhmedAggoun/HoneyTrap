from honeytrap.event_types import EventType
from honeytrap.rules.duplicate_client_metadata import (
    DuplicateClientMetadataRule,
)


def make_event(client_ip, client_port, session_id):
    return {
        "event_type": EventType.CONNECTION_OPENED,
        "client_ip": client_ip,
        "client_port": client_port,
        "session_id": session_id,
    }


def test_unique_metadata_pairs():
    rule = DuplicateClientMetadataRule()
    events = [
        make_event("192.168.1.10", 5001, "session-1"),
        make_event("192.168.1.11", 5002, "session-2"),
    ]

    assert rule.evaluate(events) == []


def test_duplicate_metadata_pair():
    rule = DuplicateClientMetadataRule()
    events = [
        make_event("192.168.1.10", 5001, "session-1"),
        make_event("192.168.1.10", 5001, "session-2"),
    ]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-016"


def test_same_ip_different_ports():
    rule = DuplicateClientMetadataRule()
    events = [
        make_event("192.168.1.10", 5001, "session-1"),
        make_event("192.168.1.10", 5002, "session-2"),
    ]

    assert rule.evaluate(events) == []


def test_same_port_different_ips():
    rule = DuplicateClientMetadataRule()
    events = [
        make_event("192.168.1.10", 5001, "session-1"),
        make_event("192.168.1.11", 5001, "session-2"),
    ]

    assert rule.evaluate(events) == []


def test_invalid_metadata_ignored():
    rule = DuplicateClientMetadataRule()
    events = [
        make_event(None, 5001, "session-1"),
        make_event("192.168.1.10", "5001", "session-2"),
        make_event("192.168.1.10", True, "session-3"),
    ]

    assert rule.evaluate(events) == []


def test_close_events_are_ignored():
    rule = DuplicateClientMetadataRule()
    events = [
        {
            **make_event("192.168.1.10", 5001, "session-1"),
            "event_type": EventType.CONNECTION_CLOSED,
        },
        {
            **make_event("192.168.1.10", 5001, "session-2"),
            "event_type": EventType.CONNECTION_CLOSED,
        },
    ]

    assert rule.evaluate(events) == []