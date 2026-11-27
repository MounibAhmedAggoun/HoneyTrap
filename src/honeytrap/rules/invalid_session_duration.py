from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class InvalidSessionDurationRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="HT-009",
            description="Detect invalid closed-session durations",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        findings = []

        for index, event in enumerate(events):
            if event.get("event_type") != EventType.CONNECTION_CLOSED:
                continue

            details = event.get("details")
            duration = details.get("duration") if isinstance(details, dict) else None

            if (
                not isinstance(duration, (int, float))
                or isinstance(duration, bool)
                or duration < 0
            ):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=(
                            f"Closed session at index {index} has invalid duration."
),
                        session_id=event.get("session_id"),
                    )
                )

        return findings