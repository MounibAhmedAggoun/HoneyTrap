from honeytrap.findings import Finding
from honeytrap.registry import RuleRegistry


class DetectionEngine:
    def __init__(self, registry: RuleRegistry):
        self.registry = registry

    def run(self, events: list[dict]) -> list[Finding]:
        findings = []

        for rule in self.registry.get_all():
            findings.extend(rule.evaluate(events))

        return findings