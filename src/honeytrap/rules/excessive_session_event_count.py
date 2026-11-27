from collections import Counter

from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class ExcessiveSessionEventCountRule(Rule):
    MAX_EVENTS = 4

    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-011",
            description="Detect sessions with excessive connection events.",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        session_counts = Counter(
            event.get("session_id")
            for event in events
            if event.get("event_type")
            in {
                EventType.CONNECTION_OPENED,
                EventType.CONNECTION_CLOSED,
            }
            and isinstance(event.get("session_id"), str)
            and event.get("session_id")
        )

        findings = []

        for session_id, count in session_counts.items():
            if count > self.MAX_EVENTS:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=(
                            f"Session contains excessive connection events "
                            f"({count} events)."
                        ),
                        session_id=session_id,
                    )
                )

        return findings