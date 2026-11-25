from collections import Counter

from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class DuplicateSessionRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="HT-002",
            description="Detect duplicate session-open events",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        opened_sessions = [
            event.get("session_id")
            for event in events
            if event.get("event_type") == EventType.CONNECTION_OPENED
            and event.get("session_id")
        ]

        counts = Counter(opened_sessions)

        findings = []

        for session_id, count in sorted(counts.items()):
            if count > 1:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Session has {count} opening events.",
                        session_id=session_id,
                    )
                )

        return findings