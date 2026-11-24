from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass
class Event:
    event_type: str
    session_id: str
    details: dict = field(default_factory=dict)
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )
    event_id: str = field(default_factory=lambda: str(uuid4()))

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "session_id": self.session_id,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }