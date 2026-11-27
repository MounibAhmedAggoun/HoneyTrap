from datetime import datetime, timedelta

from honeytrap.event_types import EventType
from honeytrap.rules.client_connection_burst import ClientConnectionBurstRule


def make_events(count, start, interval=1, client_ip="192.168.1.10"):
    base = datetime.fromisoformat(start)

    return [
        {
            "event_type": EventType.CONNECTION_OPENED,
            "client_ip": client_ip,
            "timestamp": (base + timedelta(seconds=i * interval)).isoformat(),
        }
        for i in range(count)
    ]


def test_ten_connections_no_finding():
    rule = ClientConnectionBurstRule()
    events = make_events(10, "2026-01-01T12:00:00")

    assert rule.evaluate(events) == []


def test_eleven_connections_within_window():
    rule = ClientConnectionBurstRule()
    events = make_events(11, "2026-01-01T12:00:00")

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-024"


def test_connections_spread_over_window():
    rule = ClientConnectionBurstRule()
    events = make_events(11, "2026-01-01T12:00:00", interval=4)

    assert rule.evaluate(events) == []


def test_different_ips_counted_separately():
    rule = ClientConnectionBurstRule()
    events = (
        make_events(6, "2026-01-01T12:00:00", client_ip="192.168.1.10")
        + make_events(6, "2026-01-01T12:00:00", client_ip="192.168.1.11")
    )

    assert rule.evaluate(events) == []


def test_missing_client_ip_ignored():
    rule = ClientConnectionBurstRule()
    events = make_events(11, "2026-01-01T12:00:00")

    for event in events:
        event["client_ip"] = None

    assert rule.evaluate(events) == []


def test_invalid_timestamps_ignored():
    rule = ClientConnectionBurstRule()
    events = make_events(11, "2026-01-01T12:00:00")

    for event in events:
        event["timestamp"] = "invalid"

    assert rule.evaluate(events) == []