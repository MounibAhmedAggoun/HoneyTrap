from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class MissingSessionIDRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="HT-003",
            description="Detect connection events missing a session ID",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        findings = []

        for index, event in enumerate(events):
            if event.get("event_type") not in (
                EventType.CONNECTION_OPENED,
                EventType.CONNECTION_CLOSED,
            ):
                continue

            if not event.get("session_id"):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Connection event at index {index} has no session ID.",
                    )
                )

        return findings