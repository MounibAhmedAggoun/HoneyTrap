import pytest

from honeytrap.findings import Finding, Severity
from honeytrap.rule import Rule


class ExampleRule(Rule):
    def __init__(self):
        super().__init__(
            rule_id="TEST-001",
            description="Example detection rule",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        return []


def test_rule_metadata():
    rule = ExampleRule()

    assert rule.rule_id == "TEST-001"
    assert rule.description == "Example detection rule"
    assert rule.severity == Severity.LOW


def test_rule_evaluate_returns_findings():
    rule = ExampleRule()

    result = rule.evaluate([])

    assert result == []


def test_rule_is_abstract():
    with pytest.raises(TypeError):
        Rule(
            rule_id="TEST-001",
            description="Abstract rule",
            severity=Severity.INFO,
        )


def test_rule_subclass_can_be_instantiated():
    rule = ExampleRule()

    assert isinstance(rule, Rule)