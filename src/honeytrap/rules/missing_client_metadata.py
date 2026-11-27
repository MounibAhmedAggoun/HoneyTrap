from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class MissingClientMetadataRule(Rule):
    REQUIRED_FIELDS = ("client_ip", "client_port")

    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-015",
            description="Detect connection events missing client metadata.",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        findings = []

        for event in events:
            if event.get("event_type") not in {
                EventType.CONNECTION_OPENED,
                EventType.CONNECTION_CLOSED,
            }:
                continue

            missing = [
                field
                for field in self.REQUIRED_FIELDS
                if event.get(field) is None
            ]

            if missing:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=(
                            "Connection event missing client metadata: "
                            f"{', '.join(missing)}."
                        ),
                        session_id=event.get("session_id"),
                    )
                )

        return findings