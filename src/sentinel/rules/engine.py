"""Rules engine for Sentinel.

This module provides the core rule evaluation logic, including:
- Loading rules from JSON/dict configuration
- Matching function names against patterns
- Evaluating conditions against function parameters
- Returning rule results (allow, block, require_approval)
"""

from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class RuleAction(str, Enum):
    """Actions that can be taken when a rule matches."""

    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class Condition:
    """A condition that must be met for a rule to trigger.

    Conditions check function parameters against expected values
    using various comparison operators.

    Attributes:
        param: Name of the function parameter to check.
        operator: Comparison operator (eq, ne, gt, gte, lt, lte, contains, etc.).
        value: Value to compare against.
    """

    param: str
    operator: str
    value: Any

    # Compiled regex pattern for 'matches' operator (cached)
    _compiled_pattern: re.Pattern[str] | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Compile regex pattern if using 'matches' operator."""
        if self.operator == "matches" and isinstance(self.value, str):
            self._compiled_pattern = re.compile(self.value)

    def evaluate(self, params: dict[str, Any]) -> bool:
        """Evaluate the condition against function parameters.

        Args:
            params: Dictionary of function parameter names to values.

        Returns:
            True if the condition is met, False otherwise.
        """
        if self.param not in params:
            return False

        param_value = params[self.param]

        if param_value is None:
            return False

        try:
            return self._evaluate_operator(param_value)
        except (TypeError, ValueError):
            return False

    def _evaluate_operator(self, param_value: Any) -> bool:
        """Evaluate the operator against the parameter value.

        Args:
            param_value: The value of the function parameter.

        Returns:
            True if the condition is met, False otherwise.
        """
        match self.operator:
            case "eq":
                return param_value == self.value
            case "ne":
                return param_value != self.value
            case "gt":
                return param_value > self.value
            case "gte":
                return param_value >= self.value
            case "lt":
                return param_value < self.value
            case "lte":
                return param_value <= self.value
            case "contains":
                return self.value in param_value
            case "not_contains":
                return self.value not in param_value
            case "matches":
                if self._compiled_pattern is None:
                    return False
                return bool(self._compiled_pattern.match(str(param_value)))
            case "in":
                return param_value in self.value
            case "not_in":
                return param_value not in self.value
            case _:
                return False


@dataclass
class Rule:
    """A governance rule that defines when to allow, block, or require approval.

    Rules are evaluated in priority order (lower number = higher priority).
    A rule matches if:
    1. The function name matches the pattern
    2. All conditions are met (if any)
    3. The rule is enabled

    Attributes:
        id: Unique identifier for the rule.
        name: Human-readable name.
        function_pattern: Glob pattern to match function names.
        conditions: List of conditions that must all be met.
        action: Action to take when the rule matches.
        priority: Rule priority (lower = higher priority).
        message: Message to display when rule triggers.
        enabled: Whether the rule is active.
        description: Optional detailed description.
    """

    id: str
    name: str
    function_pattern: str
    conditions: list[Condition]
    action: RuleAction
    priority: int = 100
    message: str = ""
    enabled: bool = True
    description: str = ""

    # Compiled pattern for function matching (cached)
    _compiled_fn_pattern: str | None = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Convert string action to enum if needed and compile pattern."""
        if isinstance(self.action, str):
            self.action = RuleAction(self.action)

        # Compile the function pattern for faster matching
        self._compiled_fn_pattern = self.function_pattern

    def matches_function(self, function_name: str) -> bool:
        """Check if the function name matches this rule's pattern.

        Uses glob-style pattern matching (*, ?, [seq], [!seq]).

        Args:
            function_name: The name of the function to check.

        Returns:
            True if the function name matches the pattern.
        """
        if self._compiled_fn_pattern is None:
            return False
        return fnmatch.fnmatch(function_name, self._compiled_fn_pattern)

    def evaluate(self, function_name: str, params: dict[str, Any]) -> bool:
        """Evaluate if this rule should trigger for the given function call.

        Args:
            function_name: The name of the function being called.
            params: Dictionary of function parameter names to values.

        Returns:
            True if the rule matches (function matches AND all conditions met).
        """
        if not self.enabled:
            return False

        if not self.matches_function(function_name):
            return False

        # All conditions must match
        return all(condition.evaluate(params) for condition in self.conditions)


@dataclass
class RuleResult:
    """Result of evaluating rules against a function call.

    Attributes:
        matched: Whether a rule matched.
        action: The action to take (allow, block, require_approval).
        rule_id: ID of the matching rule, or None if no match.
        message: Message from the matching rule, or None.
    """

    matched: bool
    action: RuleAction
    rule_id: str | None = None
    message: str | None = None

    @property
    def is_blocked(self) -> bool:
        """Check if the action is blocked."""
        return self.action == RuleAction.BLOCK

    @property
    def requires_approval(self) -> bool:
        """Check if the action requires approval."""
        return self.action == RuleAction.REQUIRE_APPROVAL

    @property
    def is_allowed(self) -> bool:
        """Check if the action is allowed."""
        return self.action == RuleAction.ALLOW


class RulesEngine:
    """Engine for evaluating governance rules against function calls.

    The engine loads rules from configuration, sorts them by priority,
    and evaluates them in order to determine the action for each
    function call.

    Attributes:
        rules: List of rules sorted by priority.
        default_action: Action to take when no rules match.
    """

    def __init__(
        self,
        rules: list[Rule],
        default_action: RuleAction = RuleAction.ALLOW,
    ) -> None:
        """Initialize the rules engine.

        Args:
            rules: List of rules to evaluate.
            default_action: Action to take when no rules match.
        """
        # Sort rules by priority (lower number = higher priority)
        self.rules = sorted(rules, key=lambda r: r.priority)
        self.default_action = default_action

    @classmethod
    def from_json(cls, path: Path) -> RulesEngine:
        """Load rules from a JSON file.

        Args:
            path: Path to the JSON rules file.

        Returns:
            A configured RulesEngine instance.

        Raises:
            FileNotFoundError: If the rules file doesn't exist.
            ValueError: If the rules file is invalid.
        """
        with open(path) as f:
            config = json.load(f)
        return cls.from_dict(config)

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> RulesEngine:
        """Load rules from a dictionary.

        Args:
            config: Rules configuration dictionary.

        Returns:
            A configured RulesEngine instance.

        Raises:
            ValueError: If the configuration is invalid.
        """
        rules = []

        for rule_data in config.get("rules", []):
            try:
                conditions = [
                    Condition(
                        param=c["param"],
                        operator=c["operator"],
                        value=c["value"],
                    )
                    for c in rule_data.get("conditions", [])
                ]

                rule = Rule(
                    id=rule_data["id"],
                    name=rule_data["name"],
                    function_pattern=rule_data["function_pattern"],
                    conditions=conditions,
                    action=RuleAction(rule_data["action"]),
                    priority=rule_data.get("priority", 100),
                    message=rule_data.get("message", ""),
                    enabled=rule_data.get("enabled", True),
                    description=rule_data.get("description", ""),
                )
                rules.append(rule)
            except (KeyError, ValueError) as e:
                raise ValueError(f"Invalid rule configuration: {e}") from e

        default_action_str = config.get("default_action", "allow")
        default_action = RuleAction(default_action_str)

        return cls(rules=rules, default_action=default_action)

    def evaluate(self, function_name: str, params: dict[str, Any]) -> RuleResult:
        """Evaluate rules against a function call.

        Rules are evaluated in priority order. The first matching rule
        determines the result. If no rules match, the default action is used.

        Args:
            function_name: The name of the function being called.
            params: Dictionary of function parameter names to values.

        Returns:
            RuleResult indicating the action to take.
        """
        for rule in self.rules:
            if rule.evaluate(function_name, params):
                return RuleResult(
                    matched=True,
                    action=rule.action,
                    rule_id=rule.id,
                    message=rule.message,
                )

        return RuleResult(
            matched=False,
            action=self.default_action,
            rule_id=None,
            message=None,
        )
