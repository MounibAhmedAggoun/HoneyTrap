from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class UnclosedSessionRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="HT-001",
            description="Detect sessions without a recorded closing event",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        opened_sessions = set()
        closed_sessions = set()

        for event in events:
            session_id = event.get("session_id")

            if not session_id:
                continue

            if event.get("event_type") == EventType.CONNECTION_OPENED:
                opened_sessions.add(session_id)

            elif event.get("event_type") == EventType.CONNECTION_CLOSED:
                closed_sessions.add(session_id)

        findings = []

        for session_id in sorted(opened_sessions - closed_sessions):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    message="Session has no recorded closing event.",
                    session_id=session_id,
                )
            )

        return findings