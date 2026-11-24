from datetime import UTC, datetime

from honeytrap.events import Event


def test_event_creation():
    event = Event(
        event_type="connection_opened",
        session_id="test-session",
    )

    assert event.event_type == "connection_opened"
    assert event.session_id == "test-session"
    assert event.schema_version == 1
    assert event.timestamp.tzinfo is not None


def test_event_ids_are_unique():
    event1 = Event("connection_opened", "session-1")
    event2 = Event("connection_opened", "session-1")

    assert event1.event_id != event2.event_id


def test_event_details():
    event = Event(
        event_type="connection_opened",
        session_id="test-session",
        details={"client_ip": "127.0.0.1"},
    )

    assert event.details["client_ip"] == "127.0.0.1"


def test_event_to_dict():
    timestamp = datetime(2026, 1, 1, tzinfo=UTC)
    event = Event(
        event_type="connection_opened",
        session_id="test-session",
        details={"client_ip": "127.0.0.1"},
        timestamp=timestamp,
    )

    data = event.to_dict()

    assert data["schema_version"] == 1
    assert data["event_id"] == event.event_id
    assert data["event_type"] == "connection_opened"
    assert data["session_id"] == "test-session"
    assert data["timestamp"] == timestamp.isoformat()
    assert data["details"] == {"client_ip": "127.0.0.1"}


def test_event_timestamp_is_utc():
    event = Event("connection_opened", "session-1")

    assert event.timestamp.utcoffset().total_seconds() == 0


def test_event_schema_is_consistent():
    event = Event("connection_opened", "session-1")

    assert set(event.to_dict()) == {
        "schema_version",
        "event_id",
        "event_type",
        "session_id",
        "timestamp",
        "details",
    }