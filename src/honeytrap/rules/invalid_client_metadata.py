from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class InvalidClientMetadataRule(Rule):
    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-017",
            description="Detect invalid client metadata.",
            severity=Severity.MEDIUM,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        findings = []

        for event in events:
            if event.get("event_type") != EventType.CONNECTION_OPENED:
                continue

            client_ip = event.get("client_ip")
            client_port = event.get("client_port")

            invalid_ip = (
                not isinstance(client_ip, str)
                or not client_ip.strip()
            )
            invalid_port = (
                not isinstance(client_port, int)
                or isinstance(client_port, bool)
                or not 1 <= client_port <= 65535
            )

            if invalid_ip or invalid_port:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message="Invalid client metadata detected.",
                        session_id=event.get("session_id"),
                        timestamp=event.get("timestamp"),
                    )
                )

        return findings