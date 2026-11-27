from honeytrap.event_types import EventType
from honeytrap.rules.missing_client_metadata import (
    MissingClientMetadataRule,
)


def make_event(event_type, client_ip="127.0.0.1", client_port=8080):
    return {
        "event_type": event_type,
        "client_ip": client_ip,
        "client_port": client_port,
        "session_id": "session-1",
    }


def test_complete_metadata():
    rule = MissingClientMetadataRule()
    events = [make_event(EventType.CONNECTION_OPENED)]

    assert rule.evaluate(events) == []


def test_missing_client_ip():
    rule = MissingClientMetadataRule()
    events = [make_event(EventType.CONNECTION_OPENED, client_ip=None)]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert "client_ip" in findings[0].message


def test_missing_client_port():
    rule = MissingClientMetadataRule()
    events = [make_event(EventType.CONNECTION_OPENED, client_port=None)]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert "client_port" in findings[0].message


def test_missing_both_fields():
    rule = MissingClientMetadataRule()
    events = [
        make_event(
            EventType.CONNECTION_OPENED,
            client_ip=None,
            client_port=None,
        )
    ]

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert "client_ip" in findings[0].message
    assert "client_port" in findings[0].message


def test_unrelated_event_is_ignored():
    rule = MissingClientMetadataRule()
    events = [
        make_event("unknown_event", client_ip=None, client_port=None)
    ]

    assert rule.evaluate(events) == []