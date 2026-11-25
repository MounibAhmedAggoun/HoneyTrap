from honeytrap.detection import DetectionEngine
from honeytrap.findings import Finding, Severity
from honeytrap.registry import RuleRegistry
from honeytrap.rule import Rule


class MockRule(Rule):
    def __init__(self, findings: list[Finding]):
        super().__init__(
            rule_id="MOCK-001",
            description="Mock detection rule",
            severity=Severity.INFO,
        )
        self.findings = findings

    def evaluate(self, events: list[dict]) -> list[Finding]:
        return self.findings


def test_engine_with_no_rules():
    engine = DetectionEngine(RuleRegistry())

    assert engine.run([]) == []


def test_engine_runs_registered_rule():
    finding = Finding("MOCK-001", Severity.INFO, "Test finding")
    registry = RuleRegistry()
    registry.register(MockRule([finding]))

    engine = DetectionEngine(registry)
    result = engine.run([])

    assert result == [finding]


def test_engine_collects_multiple_findings():
    first = Finding("MOCK-001", Severity.LOW, "First")
    second = Finding("MOCK-001", Severity.MEDIUM, "Second")

    registry = RuleRegistry()
    registry.register(MockRule([first, second]))

    engine = DetectionEngine(registry)

    assert engine.run([]) == [first, second]


def test_engine_passes_events_to_rules():
    class EventCheckingRule(MockRule):
        def evaluate(self, events: list[dict]) -> list[Finding]:
            assert events == [{"event_type": "test"}]
            return []

    registry = RuleRegistry()
    registry.register(EventCheckingRule([]))

    engine = DetectionEngine(registry)

    assert engine.run([{"event_type": "test"}]) == []