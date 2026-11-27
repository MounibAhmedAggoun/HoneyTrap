from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class SessionIDReuseRule(Rule):
    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-012",
            description="Detect session IDs reused across multiple lifecycles.",
            severity=Severity.MEDIUM,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        open_counts = {}

        for event in events:
            if (
                event.get("event_type") == EventType.CONNECTION_OPENED
                and isinstance(event.get("session_id"), str)
                and event.get("session_id")
            ):
                session_id = event["session_id"]
                open_counts[session_id] = open_counts.get(session_id, 0) + 1

        findings = []

        for session_id, count in open_counts.items():
            if count > 1:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=(
                            "Session ID reused across multiple "
                            f"lifecycles ({count} opens)."
                        ),
                        session_id=session_id,
                    )
                )

        return findings