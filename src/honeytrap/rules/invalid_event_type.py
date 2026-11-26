from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class InvalidEventTypeRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="HT-005",
            description="Detect missing or unrecognized event types",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        valid_types = {event_type.value for event_type in EventType}
        findings = []

        for index, event in enumerate(events):
            event_type = event.get("event_type")

            if not isinstance(event_type, str) or event_type not in valid_types:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Event at index {index} has an invalid event type.",
                    )
                )

        return findings