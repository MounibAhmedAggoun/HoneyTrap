from honeytrap.events import Event
from honeytrap.storage import EventStorage


def test_save_event(tmp_path):
    storage = EventStorage(tmp_path / "events.jsonl")
    event = Event(
        event_type="connection_opened",
        session_id="test-session",
    )

    storage.save(event)

    data = storage.load_all()

    assert len(data) == 1
    assert data[0]["event_type"] == "connection_opened"


def test_multiple_events(tmp_path):
    storage = EventStorage(tmp_path / "events.jsonl")

    storage.save(Event("connection_opened", "session-1"))
    storage.save(Event("connection_closed", "session-1"))

    assert len(storage.load_all()) == 2


def test_load_empty_storage(tmp_path):
    storage = EventStorage(tmp_path / "events.jsonl")

    assert storage.load_all() == []


def test_storage_creates_directory(tmp_path):
    storage = EventStorage(tmp_path / "nested" / "data" / "events.jsonl")

    storage.save(Event("connection_opened", "session-1"))

    assert storage.file_path.exists()