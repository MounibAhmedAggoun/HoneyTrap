from collections import Counter

from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class DuplicateSessionCloseRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="HT-007",
            description="Detect duplicate session-close events",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        closed_sessions = [
            event.get("session_id")
            for event in events
            if event.get("event_type") == EventType.CONNECTION_CLOSED
            and event.get("session_id")
        ]

        counts = Counter(closed_sessions)
        findings = []

        for count in sorted(counts.values()):
            if count > 1:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=(
                            f"Duplicate session-close events ({count} occurrences)."
                        ),
                    )
                )

        return findings