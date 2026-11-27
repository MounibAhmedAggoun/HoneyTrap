from collections import Counter

from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class DuplicateClientMetadataRule(Rule):
    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-016",
            description="Detect repeated client metadata combinations.",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        metadata = [
            (event.get("client_ip"), event.get("client_port"))
            for event in events
            if event.get("event_type") == EventType.CONNECTION_OPENED
            and isinstance(event.get("client_ip"), str)
            and isinstance(event.get("client_port"), int)
            and not isinstance(event.get("client_port"), bool)
        ]

        counts = Counter(metadata)
        findings = []

        for _, count in counts.items():
            if count > 1:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=(
                            "Repeated client metadata combination detected "
                            f"({count} occurrences)."
                        ),
                    )
                )

        return findings