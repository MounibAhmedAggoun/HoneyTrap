import logging
import socket
import threading

from honeytrap.config import ServerConfig
from honeytrap.events import Event
from honeytrap.session import Session
from honeytrap.storage import EventStorage

logger = logging.getLogger(__name__)


class TCPServer:
    def __init__(
        self,
        config: ServerConfig | None = None,
        storage: EventStorage | None = None,
    ):
        self.config = config or ServerConfig()

        self.host = self.config.host
        self.port = self.config.port
        self.max_connections = self.config.max_connections
        self.timeout = self.config.timeout

        self.storage = storage or EventStorage()

        self.server_socket: socket.socket | None = None
        self.running = False

        self.sessions: dict[str, Session] = {}
        self.events: list[Event] = []

        self._active_connections = 0
        self._lock = threading.Lock()

    def _record_event(self, event: Event) -> None:
        self.events.append(event)
        self.storage.save(event)

    def start(self) -> None:
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.max_connections)
        self.server_socket.settimeout(1.0)

        self.running = True

        logger.info("HoneyTrap listening on %s:%s", self.host, self.port)

        try:
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self.running:
                        raise
                    break

                with self._lock:
                    if self._active_connections >= self.max_connections:
                        client_socket.close()
                        continue

                    self._active_connections += 1

                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address),
                    daemon=True,
                )
                thread.start()

        finally:
            self.stop()

    def _handle_client(
        self,
        client_socket: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        session = Session(
            client_ip=client_address[0],
            client_port=client_address[1],
        )

        self.sessions[session.session_id] = session

        self._record_event(
            Event(
                event_type="connection_opened",
                session_id=session.session_id,
                details={
                    "client_ip": session.client_ip,
                    "client_port": session.client_port,
                },
            )
        )

        client_socket.settimeout(self.timeout)

        try:
            while self.running:
                try:
                    data = client_socket.recv(1024)
                except TimeoutError:
                    break

                if not data:
                    break

        except OSError as exc:
            logger.debug("Connection error: %s", exc)

        finally:
            client_socket.close()
            session.close()

            self._record_event(
                Event(
                    event_type="connection_closed",
                    session_id=session.session_id,
                    details={
                        "duration": session.duration,
                    },
                )
            )

            with self._lock:
                self._active_connections -= 1

    def stop(self) -> None:
        self.running = False

        if self.server_socket:
            try:
                self.server_socket.close()
            except OSError:
                pass

        logger.info("HoneyTrap server stopped")