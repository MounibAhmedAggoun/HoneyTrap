import socket
import threading
import time

from honeytrap.server import TCPServer


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_server(port, timeout=3):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)

    raise TimeoutError("Server did not start in time")


def test_server_accepts_connection_and_tracks_session():
    port = get_free_port()
    server = TCPServer(port=port)

    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()

    wait_for_server(port)

    client = socket.create_connection(("127.0.0.1", port))
    client.close()

    deadline = time.monotonic() + 3

    while time.monotonic() < deadline:
        if server.sessions and any(not s.is_active for s in server.sessions.values()):
            break
        time.sleep(0.05)

    server.stop()
    thread.join(timeout=3)

    assert len(server.sessions) >= 1
    assert any(not session.is_active for session in server.sessions.values())
    assert any(event.event_type == "connection_opened" for event in server.events)
    assert any(event.event_type == "connection_closed" for event in server.events)


def test_server_stops_cleanly():
    port = get_free_port()
    server = TCPServer(port=port)

    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()

    wait_for_server(port)

    server.stop()
    thread.join(timeout=3)

    assert not server.running
    assert not thread.is_alive()