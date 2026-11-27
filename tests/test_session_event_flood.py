from datetime import datetime, timedelta

from honeytrap.rules.session_event_flood import SessionEventFloodRule


def make_events(count, start, interval=1, session_id="session-1"):
    base = datetime.fromisoformat(start)

    return [
        {
            "session_id": session_id,
            "timestamp": (base + timedelta(seconds=i * interval)).isoformat(),
        }
        for i in range(count)
    ]


def test_twenty_events_no_finding():
    rule = SessionEventFloodRule()
    events = make_events(20, "2026-01-01T12:00:00")

    assert rule.evaluate(events) == []


def test_twenty_one_events_within_window():
    rule = SessionEventFloodRule()
    events = make_events(21, "2026-01-01T12:00:00")

    findings = rule.evaluate(events)

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-023"


def test_events_spread_over_time():
    rule = SessionEventFloodRule()
    events = make_events(21, "2026-01-01T12:00:00", interval=4)

    assert rule.evaluate(events) == []


def test_multiple_sessions_counted_separately():
    rule = SessionEventFloodRule()
    events = (
        make_events(11, "2026-01-01T12:00:00", session_id="session-1")
        + make_events(11, "2026-01-01T12:00:00", session_id="session-2")
    )

    assert rule.evaluate(events) == []


def test_missing_session_id_ignored():
    rule = SessionEventFloodRule()
    events = make_events(21, "2026-01-01T12:00:00")

    for event in events:
        event["session_id"] = None

    assert rule.evaluate(events) == []


def test_invalid_timestamps_ignored():
    rule = SessionEventFloodRule()
    events = make_events(21, "2026-01-01T12:00:00")

    for event in events:
        event["timestamp"] = "invalid"

    assert rule.evaluate(events) == []