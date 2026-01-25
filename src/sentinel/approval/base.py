"""Base classes for approval interfaces.

This module defines the abstract base class and data models for
approval interfaces. Implementations include terminal, REST API,
Slack, and push notifications.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
import uuid


class ApprovalStatus(str, Enum):
    """Status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ApprovalRequest:
    """Request for human approval of an action.

    Attributes:
        function_name: Name of the function requiring approval.
        parameters: Dictionary of function parameter names to values.
        rule_id: ID of the rule that triggered the approval requirement.
        message: Message explaining why approval is needed.
        action_id: Unique identifier for this approval request.
        agent_id: Optional identifier for the agent making the request.
        context: Additional context for the approver (from context_fn).
        created_at: Timestamp when the request was created.
        metadata: Additional metadata for the request.
    """

    function_name: str
    parameters: dict[str, Any]
    rule_id: str
    message: str
    action_id: str | None = None
    agent_id: str | None = None
    context: dict[str, Any] | None = None
    created_at: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Generate action_id if not provided."""
        if self.action_id is None:
            self.action_id = str(uuid.uuid4())


@dataclass
class ApprovalResult:
    """Result of an approval request.

    Attributes:
        status: Status of the approval (approved, denied, timeout, error).
        action_id: ID of the approval request this result is for.
        approved_by: Identifier of the approver (email, username, etc.).
        reason: Optional reason for the decision.
        decided_at: Timestamp when the decision was made.
        timeout_seconds: Timeout duration (set when status is TIMEOUT).
        metadata: Additional metadata for the result.
    """

    status: ApprovalStatus
    action_id: str
    approved_by: str | None = None
    reason: str | None = None
    decided_at: datetime = field(default_factory=datetime.now)
    timeout_seconds: float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_approved(self) -> bool:
        """Check if the request was approved."""
        return self.status == ApprovalStatus.APPROVED

    @property
    def is_denied(self) -> bool:
        """Check if the request was denied."""
        return self.status == ApprovalStatus.DENIED

    @property
    def is_timeout(self) -> bool:
        """Check if the request timed out."""
        return self.status == ApprovalStatus.TIMEOUT

    @property
    def is_error(self) -> bool:
        """Check if there was an error processing the request."""
        return self.status == ApprovalStatus.ERROR


class ApprovalInterface(ABC):
    """Abstract base class for approval interfaces.

    Implementations must provide the request_approval method that
    sends an approval request to a human and returns the result.

    The interface is async to avoid blocking the event loop when
    waiting for approval.
    """

    @abstractmethod
    async def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        """Request approval for an action.

        This method sends an approval request to a human through
        the implemented channel (terminal, API, Slack, etc.) and
        waits for a response.

        Args:
            request: The approval request containing action details.

        Returns:
            ApprovalResult indicating whether the action was approved,
            denied, or timed out.
        """
        pass

    def format_request(self, request: ApprovalRequest) -> str:
        """Format an approval request for display.

        Subclasses can override this to customize the display format.

        Args:
            request: The approval request to format.

        Returns:
            A formatted string representation of the request.
        """
        lines = [
            "=" * 60,
            "SENTINEL APPROVAL REQUEST",
            "=" * 60,
            f"Action ID: {request.action_id}",
            f"Function: {request.function_name}",
            f"Rule: {request.rule_id}",
            "",
            "Parameters:",
        ]

        for key, value in request.parameters.items():
            lines.append(f"  {key}: {value}")

        if request.context:
            lines.extend(["", "Context:"])
            for key, value in request.context.items():
                lines.append(f"  {key}: {value}")

        lines.extend(
            [
                "",
                f"Reason: {request.message}",
                "=" * 60,
            ]
        )

        return "\n".join(lines)
