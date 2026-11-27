from honeytrap.event_types import EventType
from honeytrap.rules.invalid_client_address import (
    InvalidClientAddressRule,
)


def make_event(event_type, client_ip, session_id="session-1"):
    return {
        "event_type": event_type,
        "client_ip": client_ip,
        "session_id": session_id,
    }


def test_valid_ipv4():
    rule = InvalidClientAddressRule()
    events = [make_event(EventType.CONNECTION_OPENED, "192.168.1.10")]

    assert rule.evaluate(events) == []


def test_valid_ipv6():
    rule = InvalidClientAddressRule()
    events = [make_event(EventType.CONNECTION_OPENED, "::1")]

    assert rule.evaluate(events) == []


def test_invalid_ip_address():
    rule = InvalidClientAddressRule()
    events = [make_event(EventType.CONNECTION_OPENED, "999.999.1.1")]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-013"


def test_invalid_address_string():
    rule = InvalidClientAddressRule()
    events = [make_event(EventType.CONNECTION_OPENED, "not-an-ip")]

    assert len(rule.evaluate(events)) == 1


def test_empty_address_is_ignored():
    rule = InvalidClientAddressRule()
    events = [make_event(EventType.CONNECTION_OPENED, "")]

    assert rule.evaluate(events) == []


def test_unrelated_event_is_ignored():
    rule = InvalidClientAddressRule()
    events = [make_event("unknown_event", "not-an-ip")]

    assert rule.evaluate(events) == []