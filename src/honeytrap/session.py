from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass
class Session:
    client_ip: str
    client_port: int
    connected_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )
    session_id: str = field(default_factory=lambda: str(uuid4()))
    disconnected_at: datetime | None = None

    @property
    def is_active(self) -> bool:
        return self.disconnected_at is None

    def close(self) -> None:
        if self.is_active:
            self.disconnected_at = datetime.now(UTC)

    @property
    def duration(self) -> float | None:
        if self.is_active:
            return None

        return (self.disconnected_at - self.connected_at).total_seconds()