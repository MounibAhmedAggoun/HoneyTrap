from honeytrap.event_types import EventType


def test_connection_opened_value():
    assert EventType.CONNECTION_OPENED == "connection_opened"


def test_connection_closed_value():
    assert EventType.CONNECTION_CLOSED == "connection_closed"


def test_event_types_are_unique():
    assert len(EventType) == len(set(EventType))