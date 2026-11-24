import threading
from dataclasses import dataclass, field


@dataclass
class ServerStats:
    total_connections: int = 0
    active_connections: int = 0
    rejected_connections: int = 0
    _lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )

    def connection_opened(self) -> None:
        with self._lock:
            self.total_connections += 1
            self.active_connections += 1

    def connection_closed(self) -> None:
        with self._lock:
            if self.active_connections > 0:
                self.active_connections -= 1

    def connection_rejected(self) -> None:
        with self._lock:
            self.rejected_connections += 1

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "total_connections": self.total_connections,
                "active_connections": self.active_connections,
                "rejected_connections": self.rejected_connections,
            }