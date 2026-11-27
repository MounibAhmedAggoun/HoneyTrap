from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class InvalidEventDataRule(Rule):
    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-018",
            description="Detect invalid event data.",
            severity=Severity.MEDIUM,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        findings = []

        valid_types = {
            EventType.CONNECTION_OPENED,
            EventType.CONNECTION_CLOSED,
        }

        for event in events:
            if event.get("event_type") not in valid_types:
                continue

            session_id = event.get("session_id")
            timestamp = event.get("timestamp")

            invalid_session_id = (
                not isinstance(session_id, str)
                or not session_id.strip()
            )
            invalid_timestamp = (
                not isinstance(timestamp, str)
                or not timestamp.strip()
            )

            if invalid_session_id or invalid_timestamp:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message="Invalid event data detected.",
                        session_id=session_id,
                        timestamp=timestamp,
                    )
                )

        return findings