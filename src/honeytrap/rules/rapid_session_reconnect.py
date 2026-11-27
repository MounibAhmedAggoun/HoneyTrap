from datetime import datetime, timedelta

from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class RapidSessionReconnectRule(Rule):
    RECONNECT_WINDOW = timedelta(seconds=5)

    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-021",
            description="Detect rapid client reconnections.",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        clients = {}

        for event in events:
            client_ip = event.get("client_ip")
            timestamp = event.get("timestamp")

            if not isinstance(client_ip, str) or not client_ip.strip():
                continue

            if not isinstance(timestamp, str):
                continue

            try:
                parsed = datetime.fromisoformat(timestamp)
            except ValueError:
                continue

            event_type = event.get("event_type")
            clients.setdefault(client_ip, {}).setdefault(
                event_type, []
            ).append(parsed)

        findings = []

        for _, data in clients.items():
            opened = sorted(data.get(EventType.CONNECTION_OPENED, []))
            closed = sorted(data.get(EventType.CONNECTION_CLOSED, []))

            for close_time in closed:
                reconnects = [
                    open_time
                    for open_time in opened
                    if timedelta(0) <= open_time - close_time
                    <= self.RECONNECT_WINDOW
                ]

                if reconnects:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message="Rapid client reconnection detected.",
                            timestamp=min(reconnects).isoformat(),
                        )
                    )
                    break

        return findings