from collections import Counter

from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class DuplicateEventIDRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="HT-006",
            description="Detect duplicate event IDs",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        event_ids = [
            event.get("event_id")
            for event in events
            if event.get("event_id")
        ]

        counts = Counter(event_ids)
        findings = []

        for count in sorted(counts.values()):
            if count > 1:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Duplicate event ID detected ({count} occurrences).",
                    )
                )

        return findings