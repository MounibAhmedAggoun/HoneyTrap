from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class InvalidClientPortRule(Rule):
    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-014",
            description="Detect invalid client port values.",
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

            port = event.get("client_port")

            if port is None:
                continue

            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
            ):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message="Invalid client port value.",
                        session_id=event.get("session_id"),
                    )
                )

        return findings