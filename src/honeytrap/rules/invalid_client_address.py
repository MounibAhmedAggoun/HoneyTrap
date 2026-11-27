from ipaddress import ip_address

from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class InvalidClientAddressRule(Rule):
    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-013",
            description="Detect malformed client IP addresses.",
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

            address = event.get("client_ip")

            if not isinstance(address, str) or not address.strip():
                continue

            try:
                ip_address(address)
            except ValueError:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message="Invalid client IP address format.",
                        session_id=event.get("session_id"),
                    )
                )

        return findings