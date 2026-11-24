from honeytrap.event_types import EventType
from honeytrap.events import Event
from honeytrap.storage import EventStorage


def test_report_from_empty_storage(tmp_path):
    storage = EventStorage(tmp_path / "events.jsonl")

    report = storage.generate_report()

    assert report["total_events"] == 0
    assert report["connections_opened"] == 0
    assert report["connections_closed"] == 0


def test_report_from_persisted_events(tmp_path):
    storage = EventStorage(tmp_path / "events.jsonl")

    storage.save(
        Event(
            event_type=EventType.CONNECTION_OPENED,
            session_id="session-1",
        )
    )
    storage.save(
        Event(
            event_type=EventType.CONNECTION_CLOSED,
            session_id="session-1",
            details={"duration": 5.0},
        )
    )

    report = storage.generate_report()

    assert report["total_events"] == 2
    assert report["connections_opened"] == 1
    assert report["connections_closed"] == 1
    assert report["unique_sessions"] == 1
    assert report["average_duration"] == 5.0
    assert report["total_duration"] == 5.0


def test_report_reads_existing_file(tmp_path):
    file_path = tmp_path / "events.jsonl"

    file_path.write_text(
        '{"event_type":"connection_closed",'
        '"session_id":"session-1",'
        '"details":{"duration":12.0}}\n',
        encoding="utf-8",
    )

    storage = EventStorage(file_path)
    report = storage.generate_report()

    assert report["connections_closed"] == 1
    assert report["average_duration"] == 12.0