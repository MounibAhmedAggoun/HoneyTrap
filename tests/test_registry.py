import pytest

from honeytrap.findings import Finding, Severity
from honeytrap.registry import RuleRegistry
from honeytrap.rule import Rule


class DummyRule(Rule):
    def __init__(self, rule_id="TEST-001"):
        super().__init__(
            rule_id=rule_id,
            description="Test rule",
            severity=Severity.LOW,
        )

    def evaluate(self, events: list[dict]) -> list[Finding]:
        return []


def test_register_rule():
    registry = RuleRegistry()
    rule = DummyRule()

    registry.register(rule)

    assert len(registry) == 1
    assert registry.get("TEST-001") is rule


def test_duplicate_rule_rejected():
    registry = RuleRegistry()
    registry.register(DummyRule())

    with pytest.raises(ValueError):
        registry.register(DummyRule())


def test_get_unknown_rule():
    registry = RuleRegistry()

    assert registry.get("UNKNOWN") is None


def test_get_all_rules():
    registry = RuleRegistry()
    first = DummyRule("TEST-001")
    second = DummyRule("TEST-002")

    registry.register(first)
    registry.register(second)

    assert registry.get_all() == [first, second]


def test_empty_registry():
    registry = RuleRegistry()

    assert len(registry) == 0
    assert registry.get_all() == []


def test_get_all_returns_independent_list():
    registry = RuleRegistry()
    registry.register(DummyRule())

    rules = registry.get_all()
    rules.clear()

    assert len(registry) == 1