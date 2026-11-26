from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class OrphanedSessionCloseRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="HT-008",
            description="Detect session-close events without a matching opening event",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        opened_sessions = {
            event.get("session_id")
            for event in events
            if event.get("event_type") == EventType.CONNECTION_OPENED
            and event.get("session_id")
        }

        findings = []

        for event in events:
            session_id = event.get("session_id")

            if (
                event.get("event_type") == EventType.CONNECTION_CLOSED
                and session_id
                and session_id not in opened_sessions
            ):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message="Session-close event has no matching opening event.",
                        session_id=session_id,
                    )
                )

        return findings