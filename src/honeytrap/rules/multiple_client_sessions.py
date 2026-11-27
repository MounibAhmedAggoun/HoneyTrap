from collections import defaultdict

from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class MultipleClientSessionsRule(Rule):
    MAX_SESSIONS = 5

    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-022",
            description="Detect clients with excessive concurrent sessions.",
            severity=Severity.MEDIUM,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        sessions = defaultdict(set)

        for event in events:
            client_ip = event.get("client_ip")
            session_id = event.get("session_id")

            if (
                not isinstance(client_ip, str)
                or not client_ip.strip()
                or not isinstance(session_id, str)
                or not session_id.strip()
            ):
                continue

            if event.get("event_type") == EventType.CONNECTION_OPENED:
                sessions[client_ip].add(session_id)
            elif event.get("event_type") == EventType.CONNECTION_CLOSED:
                sessions[client_ip].discard(session_id)

        findings = []

        for _, session_ids in sessions.items():
            if len(session_ids) > self.MAX_SESSIONS:
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity,
                        message=(
                            "Client has more than 5 concurrent sessions "
                            f"({len(session_ids)} sessions)."
                        ),
                    )
                )

        return findings