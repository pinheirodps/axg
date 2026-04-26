from __future__ import annotations

from typing import Any

from axg.models import ConditionGroup, PolicyRule, RuleCondition


MISSING = object()


class RuleEngine:
    supported_operators = {
        "eq",
        "neq",
        "gt",
        "gte",
        "lt",
        "lte",
        "in",
        "not_in",
        "exists",
        "contains",
    }

    def evaluate_rules(self, rules: list[PolicyRule], data: dict[str, Any]) -> list[PolicyRule]:
        return [rule for rule in rules if self.evaluate_group(rule.condition, data)]

    def evaluate_group(self, group: ConditionGroup, data: dict[str, Any]) -> bool:
        all_conditions = group.all or []
        any_conditions = group.any or []

        all_matches = True
        if all_conditions:
            all_matches = all(self.evaluate_condition(condition, data) for condition in all_conditions)

        any_matches = True
        if any_conditions:
            any_matches = any(self.evaluate_condition(condition, data) for condition in any_conditions)

        return all_matches and any_matches

    def evaluate_condition(self, condition: RuleCondition, data: dict[str, Any]) -> bool:
        if condition.operator not in self.supported_operators:
            return False

        actual = self._field_value(data, condition.field)
        expected = condition.value

        if condition.operator == "exists":
            return actual is not MISSING
        if actual is MISSING:
            return False
        if condition.operator == "eq":
            return actual == expected
        if condition.operator == "neq":
            return actual != expected
        if condition.operator == "gt":
            return self._numeric_compare(actual, expected, lambda a, b: a > b)
        if condition.operator == "gte":
            return self._numeric_compare(actual, expected, lambda a, b: a >= b)
        if condition.operator == "lt":
            return self._numeric_compare(actual, expected, lambda a, b: a < b)
        if condition.operator == "lte":
            return self._numeric_compare(actual, expected, lambda a, b: a <= b)
        if condition.operator == "in":
            return isinstance(expected, list) and actual in expected
        if condition.operator == "not_in":
            return isinstance(expected, list) and actual not in expected
        if condition.operator == "contains":
            return self._contains(actual, expected)
        return False

    def _field_value(self, data: dict[str, Any], path: str) -> Any:
        current: Any = data
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
                continue
            return MISSING
        return current

    def _numeric_compare(self, actual: Any, expected: Any, comparator) -> bool:
        try:
            return comparator(float(actual), float(expected))
        except (TypeError, ValueError):
            return False

    def _contains(self, actual: Any, expected: Any) -> bool:
        if isinstance(actual, str):
            return str(expected).lower() in actual.lower()
        if isinstance(actual, list):
            return expected in actual
        return False

