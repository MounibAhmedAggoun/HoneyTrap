from abc import ABC, abstractmethod

from honeytrap.findings import Finding, Severity


class Rule(ABC):
    def __init__(
        self,
        rule_id: str,
        description: str,
        severity: Severity,
    ):
        self.rule_id = rule_id
        self.description = description
        self.severity = severity

    @abstractmethod
    def evaluate(self, events: list[dict]) -> list[Finding]:
        """Evaluate events and return findings."""
        raise NotImplementedError