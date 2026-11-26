from datetime import datetime

from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class InvalidTimestampRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="HT-004",
            description="Detect events with missing or invalid timestamps",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        findings = []

        for index, event in enumerate(events):
            timestamp = event.get("timestamp")

            if not isinstance(timestamp, str) or not timestamp.strip():
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Event at index {index} has a missing timestamp.",
                    )
                )
                continue

            try:
                datetime.fromisoformat(timestamp)
            except ValueError:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=f"Event at index {index} has an invalid timestamp.",
                    )
                )

        return findings