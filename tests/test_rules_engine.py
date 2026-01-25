"""Tests for the Sentinel rules engine."""

import pytest
from pathlib import Path
from typing import Any

from sentinel.rules.engine import RulesEngine, Rule, Condition, RuleResult, RuleAction


FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestCondition:
    """Tests for condition evaluation."""

    def test_eq_operator_matches(self) -> None:
        """Test equality operator returns True when values match."""
        condition = Condition(param="status", operator="eq", value="active")
        assert condition.evaluate({"status": "active"}) is True

    def test_eq_operator_no_match(self) -> None:
        """Test equality operator returns False when values don't match."""
        condition = Condition(param="status", operator="eq", value="active")
        assert condition.evaluate({"status": "inactive"}) is False

    def test_ne_operator(self) -> None:
        """Test not-equal operator."""
        condition = Condition(param="status", operator="ne", value="deleted")
        assert condition.evaluate({"status": "active"}) is True
        assert condition.evaluate({"status": "deleted"}) is False

    def test_gt_operator(self) -> None:
        """Test greater-than operator."""
        condition = Condition(param="amount", operator="gt", value=100)
        assert condition.evaluate({"amount": 150}) is True
        assert condition.evaluate({"amount": 100}) is False
        assert condition.evaluate({"amount": 50}) is False

    def test_gte_operator(self) -> None:
        """Test greater-than-or-equal operator."""
        condition = Condition(param="amount", operator="gte", value=100)
        assert condition.evaluate({"amount": 150}) is True
        assert condition.evaluate({"amount": 100}) is True
        assert condition.evaluate({"amount": 50}) is False

    def test_lt_operator(self) -> None:
        """Test less-than operator."""
        condition = Condition(param="amount", operator="lt", value=100)
        assert condition.evaluate({"amount": 50}) is True
        assert condition.evaluate({"amount": 100}) is False
        assert condition.evaluate({"amount": 150}) is False

    def test_lte_operator(self) -> None:
        """Test less-than-or-equal operator."""
        condition = Condition(param="amount", operator="lte", value=100)
        assert condition.evaluate({"amount": 50}) is True
        assert condition.evaluate({"amount": 100}) is True
        assert condition.evaluate({"amount": 150}) is False

    def test_contains_operator(self) -> None:
        """Test contains operator for strings."""
        condition = Condition(param="email", operator="contains", value="@company.com")
        assert condition.evaluate({"email": "user@company.com"}) is True
        assert condition.evaluate({"email": "user@other.com"}) is False

    def test_not_contains_operator(self) -> None:
        """Test not_contains operator for strings."""
        condition = Condition(param="email", operator="not_contains", value="@competitor.com")
        assert condition.evaluate({"email": "user@company.com"}) is True
        assert condition.evaluate({"email": "user@competitor.com"}) is False

    def test_matches_operator_regex(self) -> None:
        """Test regex matches operator."""
        condition = Condition(param="code", operator="matches", value=r"^[A-Z]{3}-\d{4}$")
        assert condition.evaluate({"code": "ABC-1234"}) is True
        assert condition.evaluate({"code": "abc-1234"}) is False
        assert condition.evaluate({"code": "ABCD-123"}) is False

    def test_in_operator(self) -> None:
        """Test in operator for list membership."""
        condition = Condition(param="status", operator="in", value=["active", "pending"])
        assert condition.evaluate({"status": "active"}) is True
        assert condition.evaluate({"status": "pending"}) is True
        assert condition.evaluate({"status": "deleted"}) is False

    def test_not_in_operator(self) -> None:
        """Test not_in operator for list exclusion."""
        condition = Condition(param="status", operator="not_in", value=["deleted", "archived"])
        assert condition.evaluate({"status": "active"}) is True
        assert condition.evaluate({"status": "deleted"}) is False

    def test_missing_param_returns_false(self) -> None:
        """Test that missing parameter returns False."""
        condition = Condition(param="amount", operator="gt", value=100)
        assert condition.evaluate({"other_param": 200}) is False

    def test_none_value_handling(self) -> None:
        """Test handling of None values."""
        condition = Condition(param="amount", operator="gt", value=100)
        assert condition.evaluate({"amount": None}) is False


class TestRule:
    """Tests for rule matching and evaluation."""

    def test_rule_matches_function_pattern_exact(self) -> None:
        """Test exact function name matching."""
        rule = Rule(
            id="test",
            name="Test Rule",
            function_pattern="transfer_funds",
            conditions=[],
            action=RuleAction.BLOCK,
            priority=10,
            message="Blocked",
        )
        assert rule.matches_function("transfer_funds") is True
        assert rule.matches_function("transfer_other") is False

    def test_rule_matches_function_pattern_wildcard_suffix(self) -> None:
        """Test wildcard suffix pattern matching."""
        rule = Rule(
            id="test",
            name="Test Rule",
            function_pattern="transfer_*",
            conditions=[],
            action=RuleAction.BLOCK,
            priority=10,
            message="Blocked",
        )
        assert rule.matches_function("transfer_funds") is True
        assert rule.matches_function("transfer_money") is True
        assert rule.matches_function("send_transfer") is False

    def test_rule_matches_function_pattern_wildcard_prefix(self) -> None:
        """Test wildcard prefix pattern matching."""
        rule = Rule(
            id="test",
            name="Test Rule",
            function_pattern="*_delete",
            conditions=[],
            action=RuleAction.BLOCK,
            priority=10,
            message="Blocked",
        )
        assert rule.matches_function("user_delete") is True
        assert rule.matches_function("file_delete") is True
        assert rule.matches_function("delete_user") is False

    def test_rule_matches_function_pattern_wildcard_both(self) -> None:
        """Test wildcard on both sides pattern matching."""
        rule = Rule(
            id="test",
            name="Test Rule",
            function_pattern="*_admin_*",
            conditions=[],
            action=RuleAction.BLOCK,
            priority=10,
            message="Blocked",
        )
        assert rule.matches_function("get_admin_users") is True
        assert rule.matches_function("set_admin_role") is True
        assert rule.matches_function("admin_panel") is False

    def test_rule_evaluates_all_conditions(self) -> None:
        """Test that all conditions must match for rule to trigger."""
        rule = Rule(
            id="test",
            name="Test Rule",
            function_pattern="execute_trade",
            conditions=[
                Condition(param="amount", operator="gt", value=1000),
                Condition(param="market", operator="eq", value="crypto"),
            ],
            action=RuleAction.REQUIRE_APPROVAL,
            priority=10,
            message="Requires approval",
        )
        # Both conditions match
        assert rule.evaluate("execute_trade", {"amount": 1500, "market": "crypto"}) is True
        # Only one condition matches
        assert rule.evaluate("execute_trade", {"amount": 1500, "market": "stocks"}) is False
        assert rule.evaluate("execute_trade", {"amount": 500, "market": "crypto"}) is False
        # Function doesn't match
        assert rule.evaluate("other_function", {"amount": 1500, "market": "crypto"}) is False

    def test_rule_with_no_conditions_matches_function_only(self) -> None:
        """Test that rule with no conditions matches any params."""
        rule = Rule(
            id="test",
            name="Test Rule",
            function_pattern="delete_*",
            conditions=[],
            action=RuleAction.BLOCK,
            priority=10,
            message="Blocked",
        )
        assert rule.evaluate("delete_user", {}) is True
        assert rule.evaluate("delete_file", {"file_id": 123}) is True

    def test_disabled_rule_never_matches(self) -> None:
        """Test that disabled rules don't match."""
        rule = Rule(
            id="test",
            name="Test Rule",
            function_pattern="delete_*",
            conditions=[],
            action=RuleAction.BLOCK,
            priority=10,
            message="Blocked",
            enabled=False,
        )
        assert rule.evaluate("delete_user", {}) is False


class TestRulesEngine:
    """Tests for the rules engine."""

    def test_load_rules_from_json(self) -> None:
        """Test loading rules from JSON file."""
        engine = RulesEngine.from_json(FIXTURES_DIR / "sample_rules.json")
        assert len(engine.rules) == 5

    def test_load_rules_from_dict(self) -> None:
        """Test loading rules from dictionary."""
        config = {
            "version": "1.0",
            "default_action": "allow",
            "rules": [
                {
                    "id": "test_rule",
                    "name": "Test Rule",
                    "function_pattern": "test_*",
                    "conditions": [],
                    "action": "block",
                    "priority": 10,
                    "message": "Blocked",
                }
            ],
        }
        engine = RulesEngine.from_dict(config)
        assert len(engine.rules) == 1

    def test_rules_sorted_by_priority(self) -> None:
        """Test that rules are sorted by priority (lower = higher priority)."""
        config = {
            "version": "1.0",
            "default_action": "allow",
            "rules": [
                {
                    "id": "low_priority",
                    "name": "Low Priority",
                    "function_pattern": "test_*",
                    "conditions": [],
                    "action": "allow",
                    "priority": 100,
                    "message": "Allowed",
                },
                {
                    "id": "high_priority",
                    "name": "High Priority",
                    "function_pattern": "test_*",
                    "conditions": [],
                    "action": "block",
                    "priority": 1,
                    "message": "Blocked",
                },
            ],
        }
        engine = RulesEngine.from_dict(config)
        assert engine.rules[0].id == "high_priority"
        assert engine.rules[1].id == "low_priority"

    def test_evaluate_returns_first_matching_rule(self) -> None:
        """Test that evaluate returns the first matching rule by priority."""
        engine = RulesEngine.from_json(FIXTURES_DIR / "sample_rules.json")
        result = engine.evaluate("delete_user", {})

        assert result.matched is True
        assert result.action == RuleAction.BLOCK
        assert result.rule_id == "test_block_delete"

    def test_evaluate_returns_default_action_when_no_match(self) -> None:
        """Test that default action is returned when no rules match."""
        engine = RulesEngine.from_json(FIXTURES_DIR / "sample_rules.json")
        result = engine.evaluate("unknown_function", {})

        assert result.matched is False
        assert result.action == RuleAction.ALLOW
        assert result.rule_id is None

    def test_evaluate_with_conditions(self) -> None:
        """Test evaluation with conditional rules."""
        engine = RulesEngine.from_json(FIXTURES_DIR / "sample_rules.json")

        # Should require approval (amount > 100)
        result = engine.evaluate("transfer_funds", {"amount": 150})
        assert result.action == RuleAction.REQUIRE_APPROVAL

        # Should allow (amount <= 100, no rule matches)
        result = engine.evaluate("transfer_funds", {"amount": 50})
        assert result.action == RuleAction.ALLOW

    def test_evaluate_multiple_conditions(self) -> None:
        """Test evaluation with multiple conditions that must all match."""
        engine = RulesEngine.from_json(FIXTURES_DIR / "sample_rules.json")

        # Both conditions match
        result = engine.evaluate("execute_trade", {"amount": 1500, "market": "crypto"})
        assert result.action == RuleAction.REQUIRE_APPROVAL

        # Only one condition matches
        result = engine.evaluate("execute_trade", {"amount": 1500, "market": "stocks"})
        assert result.action == RuleAction.ALLOW

    def test_evaluate_contains_condition(self) -> None:
        """Test evaluation with contains condition."""
        engine = RulesEngine.from_json(FIXTURES_DIR / "sample_rules.json")

        # Should block (email contains @competitor.com)
        result = engine.evaluate("send_email", {"to": "user@competitor.com"})
        assert result.action == RuleAction.BLOCK

        # Should allow (email doesn't contain @competitor.com)
        result = engine.evaluate("send_email", {"to": "user@partner.com"})
        assert result.action == RuleAction.ALLOW

    def test_evaluate_performance_100_rules(self) -> None:
        """Test that evaluation of 100 rules completes in < 10ms."""
        import time

        rules = [
            {
                "id": f"rule_{i}",
                "name": f"Rule {i}",
                "function_pattern": f"function_{i}_*",
                "conditions": [{"param": "value", "operator": "gt", "value": i}],
                "action": "block",
                "priority": i,
                "message": f"Blocked by rule {i}",
            }
            for i in range(100)
        ]

        config = {"version": "1.0", "default_action": "allow", "rules": rules}
        engine = RulesEngine.from_dict(config)

        # Warm up
        engine.evaluate("test_function", {"value": 50})

        # Measure
        start = time.perf_counter()
        for _ in range(100):
            engine.evaluate("function_50_test", {"value": 60})
        elapsed = (time.perf_counter() - start) / 100 * 1000  # ms per evaluation

        assert elapsed < 10, f"Evaluation took {elapsed:.2f}ms, expected < 10ms"

    def test_invalid_json_raises_error(self) -> None:
        """Test that invalid JSON raises appropriate error."""
        with pytest.raises(FileNotFoundError):
            RulesEngine.from_json(Path("/nonexistent/rules.json"))

    def test_invalid_schema_raises_error(self) -> None:
        """Test that invalid schema raises validation error."""
        config = {
            "version": "1.0",
            "rules": [
                {
                    "id": "invalid",
                    # Missing required fields
                }
            ],
        }
        with pytest.raises(ValueError):
            RulesEngine.from_dict(config)


class TestRuleResult:
    """Tests for RuleResult dataclass."""

    def test_rule_result_blocked(self) -> None:
        """Test blocked rule result."""
        result = RuleResult(
            matched=True,
            action=RuleAction.BLOCK,
            rule_id="test_rule",
            message="Action blocked",
        )
        assert result.is_blocked is True
        assert result.requires_approval is False
        assert result.is_allowed is False

    def test_rule_result_requires_approval(self) -> None:
        """Test requires_approval rule result."""
        result = RuleResult(
            matched=True,
            action=RuleAction.REQUIRE_APPROVAL,
            rule_id="test_rule",
            message="Requires approval",
        )
        assert result.is_blocked is False
        assert result.requires_approval is True
        assert result.is_allowed is False

    def test_rule_result_allowed(self) -> None:
        """Test allowed rule result."""
        result = RuleResult(
            matched=False,
            action=RuleAction.ALLOW,
            rule_id=None,
            message=None,
        )
        assert result.is_blocked is False
        assert result.requires_approval is False
        assert result.is_allowed is True
