from datetime import datetime

from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class SessionEventOrderRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="HT-010",
            description="Detect session closing before opening timestamps",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        opened = {}
        findings = []

        for event in events:
            session_id = event.get("session_id")
            timestamp = event.get("timestamp")

            if not session_id or not isinstance(timestamp, str):
                continue

            try:
                parsed = datetime.fromisoformat(timestamp)
            except ValueError:
                continue

            if event.get("event_type") == EventType.CONNECTION_OPENED:
                opened[session_id] = parsed

            elif event.get("event_type") == EventType.CONNECTION_CLOSED:
                opened_at = opened.get(session_id)

                if opened_at and parsed < opened_at:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message="Session closed before its opening timestamp.",
                            session_id=session_id,
                        )
                    )

        return findings