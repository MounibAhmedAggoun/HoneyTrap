from collections import defaultdict
from datetime import datetime, timedelta

from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class SessionEventFloodRule(Rule):
    MAX_EVENTS = 20
    WINDOW = timedelta(seconds=60)

    def __init__(self) -> None:
        super().__init__(
            rule_id="HT-023",
            description="Detect excessive event frequency within a session.",
            severity=Severity.MEDIUM,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        sessions = defaultdict(list)

        for event in events:
            session_id = event.get("session_id")
            timestamp = event.get("timestamp")

            if not isinstance(session_id, str) or not session_id.strip():
                continue

            if not isinstance(timestamp, str):
                continue

            try:
                parsed = datetime.fromisoformat(timestamp)
            except ValueError:
                continue

            sessions[session_id].append(parsed)

        findings = []

        for session_id, timestamps in sessions.items():
            timestamps.sort()

            left = 0
            for right, current in enumerate(timestamps):
                while current - timestamps[left] > self.WINDOW:
                    left += 1

                if right - left + 1 > self.MAX_EVENTS:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=self.severity,
                            message="Session event flood detected.",
                            session_id=session_id,
                            timestamp=current.isoformat(),
                        )
                    )
                    break

        return findings