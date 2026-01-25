"""Custom exceptions for Sentinel.

This module defines all custom exceptions used by Sentinel to communicate
blocking decisions, configuration errors, and other error states to the
calling agent.
"""

from typing import Any


class SentinelError(Exception):
    """Base exception for all Sentinel errors."""

    pass


class SentinelBlockedError(SentinelError):
    """Raised when an action is blocked by Sentinel.

    The agent MUST receive this exception to:
    - Inform the user that the action requires approval or was blocked
    - Try an alternative action
    - Avoid infinite retry loops

    Attributes:
        reason: Human-readable explanation of why the action was blocked.
        action: Name of the function/action that was blocked.
        awaiting_approval: Whether the action is pending human approval.
        agent_id: Optional identifier for the agent that was blocked.
    """

    def __init__(
        self,
        reason: str,
        action: str,
        awaiting_approval: bool = False,
        agent_id: str | None = None,
    ) -> None:
        """Initialize SentinelBlockedError.

        Args:
            reason: Human-readable explanation of why the action was blocked.
            action: Name of the function/action that was blocked.
            awaiting_approval: Whether the action is pending human approval.
            agent_id: Optional identifier for the agent that was blocked.
        """
        self.reason = reason
        self.action = action
        self.awaiting_approval = awaiting_approval
        self.agent_id = agent_id
        agent_prefix = f"[{agent_id}] " if agent_id else ""
        super().__init__(f"{agent_prefix}Action '{action}' blocked: {reason}")


class SentinelConfigError(SentinelError):
    """Raised when there is a configuration error.

    This includes invalid rules files, missing configuration, and
    schema validation failures.
    """

    pass


class SentinelTimeoutError(SentinelError):
    """Raised when an approval request times out.

    In fail-secure mode, this will cause the action to be blocked.
    In fail-safe mode, this may allow the action to proceed with a warning.
    """

    def __init__(self, action: str, timeout_seconds: float) -> None:
        """Initialize SentinelTimeoutError.

        Args:
            action: Name of the function/action that timed out.
            timeout_seconds: The timeout duration that was exceeded.
        """
        self.action = action
        self.timeout_seconds = timeout_seconds
        super().__init__(
            f"Approval for action '{action}' timed out after {timeout_seconds}s"
        )


class SentinelValidationError(SentinelError):
    """Raised when rule validation fails.

    This includes invalid rule schemas, missing required fields,
    and invalid condition operators.
    """

    def __init__(self, message: str, errors: list[dict[str, Any]] | None = None) -> None:
        """Initialize SentinelValidationError.

        Args:
            message: Human-readable description of the validation error.
            errors: Optional list of detailed validation errors.
        """
        self.errors = errors or []
        super().__init__(message)
