from datetime import timezone

from honeytrap.session import Session


def test_session_creation():
    session = Session(client_ip="127.0.0.1", client_port=5000)

    assert session.client_ip == "127.0.0.1"
    assert session.client_port == 5000
    assert session.is_active
    assert session.disconnected_at is None
    assert session.session_id
    assert session.connected_at.tzinfo == timezone.utc


def test_session_ids_are_unique():
    first = Session(client_ip="127.0.0.1", client_port=5000)
    second = Session(client_ip="127.0.0.1", client_port=5001)

    assert first.session_id != second.session_id


def test_session_close():
    session = Session(client_ip="127.0.0.1", client_port=5000)

    session.close()

    assert not session.is_active
    assert session.disconnected_at is not None
    assert session.duration is not None
    assert session.duration >= 0


def test_session_close_is_idempotent():
    session = Session(client_ip="127.0.0.1", client_port=5000)

    session.close()
    first_close_time = session.disconnected_at

    session.close()

    assert session.disconnected_at == first_close_time