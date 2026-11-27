from datetime import UTC, datetime, timedelta

from honeytrap.rules.future_timestamp import FutureTimestampRule


def make_event(timestamp, event_type="UNKNOWN"):
    return {
        "event_type": event_type,
        "timestamp": timestamp,
        "session_id": "session-1",
    }


def test_past_timestamp():
    rule = FutureTimestampRule()
    timestamp = (datetime.now(UTC) - timedelta(hours=1)).isoformat()

    assert rule.evaluate([make_event(timestamp)]) == []


def test_future_timestamp():
    rule = FutureTimestampRule()
    timestamp = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

    findings = rule.evaluate([make_event(timestamp)])

    assert len(findings) == 1
    assert findings[0].rule_id == "HT-020"


def test_invalid_timestamp_ignored():
    rule = FutureTimestampRule()
    assert rule.evaluate([make_event("invalid")]) == []


def test_missing_timestamp_ignored():
    rule = FutureTimestampRule()
    event = make_event(None)

    assert rule.evaluate([event]) == []


def test_unrelated_event_type_checked():
    rule = FutureTimestampRule()
    timestamp = (datetime.now(UTC) + timedelta(hours=1)).isoformat()

    findings = rule.evaluate([make_event(timestamp, "UNKNOWN")])

    assert len(findings) == 1