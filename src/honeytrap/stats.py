from dataclasses import dataclass


@dataclass
class ServerStats:
    total_connections: int = 0
    active_connections: int = 0
    rejected_connections: int = 0

    def connection_opened(self) -> None:
        self.total_connections += 1
        self.active_connections += 1

    def connection_closed(self) -> None:
        if self.active_connections > 0:
            self.active_connections -= 1

    def connection_rejected(self) -> None:
        self.rejected_connections += 1