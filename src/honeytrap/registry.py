from honeytrap.rule import Rule


class RuleRegistry:
    def __init__(self):
        self._rules: dict[str, Rule] = {}

    def register(self, rule: Rule) -> None:
        if rule.rule_id in self._rules:
            raise ValueError(f"Rule already registered: {rule.rule_id}")

        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> Rule | None:
        return self._rules.get(rule_id)

    def get_all(self) -> list[Rule]:
        return list(self._rules.values())

    def __len__(self) -> int:
        return len(self._rules)