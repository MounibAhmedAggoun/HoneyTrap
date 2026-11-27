from datetime import UTC, datetime

from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class FutureTimestampRule(Rule):
    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-020",
            description="Detect events with future timestamps.",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        findings = []
        now = datetime.now(UTC)

        for event in events:
            timestamp = event.get("timestamp")

            if not isinstance(timestamp, str) or not timestamp.strip():
                continue

            try:
                parsed = datetime.fromisoformat(timestamp)
            except ValueError:
                continue

            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)

            if parsed > now:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message="Event timestamp is in the future.",
                        session_id=event.get("session_id"),
                        timestamp=timestamp,
                    )
                )

        return findings