from datetime import timezone

from honeytrap.events import Event


def test_event_creation():
    event = Event(
        event_type="connection_opened",
        session_id="session-123",
    )

    assert event.event_type == "connection_opened"
    assert event.session_id == "session-123"
    assert event.event_id
    assert event.timestamp.tzinfo == timezone.utc
    assert event.details == {}


def test_event_ids_are_unique():
    first = Event(event_type="test", session_id="session-1")
    second = Event(event_type="test", session_id="session-1")

    assert first.event_id != second.event_id


def test_event_details():
    event = Event(
        event_type="connection_opened",
        session_id="session-123",
        details={"client_ip": "127.0.0.1", "client_port": 5000},
    )

    assert event.details["client_ip"] == "127.0.0.1"
    assert event.details["client_port"] == 5000


def test_event_to_dict():
    event = Event(
        event_type="connection_opened",
        session_id="session-123",
        details={"client_ip": "127.0.0.1"},
    )

    result = event.to_dict()

    assert result["event_id"] == event.event_id
    assert result["event_type"] == "connection_opened"
    assert result["session_id"] == "session-123"
    assert result["timestamp"] == event.timestamp.isoformat()
    assert result["details"] == {"client_ip": "127.0.0.1"}