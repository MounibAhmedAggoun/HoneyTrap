from collections import defaultdict
from datetime import datetime, timedelta

from honeytrap.event_types import EventType
from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class ClientConnectionBurstRule(Rule):
    MAX_CONNECTIONS = 10
    WINDOW = timedelta(seconds=30)

    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-024",
            description="Detect excessive client connection bursts.",
            severity=Severity.MEDIUM,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        clients = defaultdict(list)

        for event in events:
            if event.get("event_type") != EventType.CONNECTION_OPENED:
                continue

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

            clients[client_ip].append(parsed)

        findings = []

        for _, timestamps in clients.items():
            timestamps.sort()

            left = 0
            for right, current in enumerate(timestamps):
                while current - timestamps[left] > self.WINDOW:
                    left += 1

                if right - left + 1 > self.MAX_CONNECTIONS:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message="Client connection burst detected.",
                            timestamp=current.isoformat(),
                        )
                    )
                    break

        return findings