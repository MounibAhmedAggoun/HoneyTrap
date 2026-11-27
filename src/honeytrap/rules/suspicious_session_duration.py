from datetime import datetime, timedelta

from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class SuspiciousSessionDurationRule(Rule):
    MAX_DURATION = timedelta(hours=24)

    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-019",
            description="Detect suspiciously long session durations.",
            severity=Severity.MEDIUM,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        sessions = {}

        for event in events:
            session_id = event.get("session_id")
            timestamp = event.get("timestamp")

            if not isinstance(session_id, str) or not isinstance(timestamp, str):
                continue

            try:
                parsed = datetime.fromisoformat(timestamp)
            except ValueError:
                continue

            event_type = event.get("event_type")

            if event_type == EventType.CONNECTION_OPENED:
                sessions.setdefault(session_id, {})["opened"] = parsed
            elif event_type == EventType.CONNECTION_CLOSED:
                sessions.setdefault(session_id, {})["closed"] = parsed

        findings = []

        for session_id, data in sessions.items():
            opened = data.get("opened")
            closed = data.get("closed")

            if opened is None or closed is None or closed < opened:
                continue

            if closed - opened > self.MAX_DURATION:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message="Session duration exceeds 24 hours.",
                        session_id=session_id,
                        timestamp=closed.isoformat(),
                    )
                )

        return findings