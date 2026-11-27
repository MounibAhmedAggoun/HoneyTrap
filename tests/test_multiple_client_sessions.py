from honeytrap.event_types import EventType
from honeytrap.rules.multiple_client_sessions import (
    MultipleClientSessionsRule,
)


def make_event(event_type, session_id, client_ip="192.168.1.10"):
    return {
        "event_type": event_type,
        "session_id": session_id,
        "client_ip": client_ip,
    }


def test_five_sessions_no_finding():
    rule = MultipleClientSessionsRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, f"session-{i}")
        for i in range(5)
    ]

    assert rule.evaluate(events) == []


def test_six_sessions_detected():
    rule = MultipleClientSessionsRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, f"session-{i}")
        for i in range(6)
    ]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-022"


def test_different_ips_counted_separately():
    rule = MultipleClientSessionsRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, f"session-{i}", "192.168.1.10")
        for i in range(3)
    ] + [
        make_event(EventType.CONNECTION_OPENED, f"other-{i}", "192.168.1.11")
        for i in range(3)
    ]

    assert rule.evaluate(events) == []


def test_closed_sessions_excluded():
    rule = MultipleClientSessionsRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, f"session-{i}")
        for i in range(6)
    ] + [
        make_event(EventType.CONNECTION_CLOSED, f"session-{i}")
        for i in range(2)
    ]

    assert rule.evaluate(events) == []


def test_missing_client_ip_ignored():
    rule = MultipleClientSessionsRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, f"session-{i}", None)
        for i in range(6)
    ]

    assert rule.evaluate(events) == []


def test_missing_session_id_ignored():
    rule = MultipleClientSessionsRule()
    events = [
        make_event(EventType.CONNECTION_OPENED, None)
        for _ in range(6)
    ]

    assert rule.evaluate(events) == []