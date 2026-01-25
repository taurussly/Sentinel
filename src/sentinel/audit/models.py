"""Data models for audit logging.

This module defines the data structures used for audit events
in the Sentinel governance system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

# Event types for audit logging
EventType = Literal[
    "allow",
    "block",
    "approval_requested",
    "approval_granted",
    "approval_denied",
    "approval_timeout",
    "approval_error",
    "anomaly_detected",
]

# Result types
ResultType = Literal["executed", "blocked", "pending", "error", "flagged"]


@dataclass
class AuditEvent:
    """A single audit event recording a Sentinel action.

    Attributes:
        timestamp: ISO format timestamp when the event occurred.
        event_type: Type of event (allow, block, approval_*, etc.).
        function_name: Name of the function that was called.
        parameters: Dictionary of function parameters.
        result: Outcome of the action (executed, blocked, pending).
        agent_id: Optional identifier for the agent.
        rule_id: ID of the rule that triggered the action.
        context: Optional context provided by context_fn.
        approved_by: Who approved/denied (for approval events).
        reason: Reason for block/denial.
        duration_ms: Time taken to process the action.
        action_id: Unique identifier for the approval request.
        metadata: Additional metadata.
    """

    timestamp: str
    event_type: EventType
    function_name: str
    parameters: dict[str, Any]
    result: ResultType
    agent_id: str | None = None
    rule_id: str | None = None
    context: dict[str, Any] | None = None
    approved_by: str | None = None
    reason: str | None = None
    duration_ms: float = 0.0
    action_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        event_type: EventType,
        function_name: str,
        parameters: dict[str, Any],
        result: ResultType,
        **kwargs: Any,
    ) -> AuditEvent:
        """Create a new audit event with current timestamp.

        Args:
            event_type: Type of event.
            function_name: Name of the function.
            parameters: Function parameters.
            result: Result of the action.
            **kwargs: Additional fields.

        Returns:
            New AuditEvent instance.
        """
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            function_name=function_name,
            parameters=parameters,
            result=result,
            **kwargs,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary for serialization.

        Returns:
            Dictionary representation of the event.
        """
        data: dict[str, Any] = {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "function_name": self.function_name,
            "parameters": self.parameters,
            "result": self.result,
        }

        # Only include non-None optional fields
        if self.agent_id is not None:
            data["agent_id"] = self.agent_id
        if self.rule_id is not None:
            data["rule_id"] = self.rule_id
        if self.context is not None:
            data["context"] = self.context
        if self.approved_by is not None:
            data["approved_by"] = self.approved_by
        if self.reason is not None:
            data["reason"] = self.reason
        if self.duration_ms > 0:
            data["duration_ms"] = self.duration_ms
        if self.action_id is not None:
            data["action_id"] = self.action_id
        if self.metadata:
            data["metadata"] = self.metadata

        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEvent:
        """Create event from dictionary.

        Args:
            data: Dictionary with event data.

        Returns:
            AuditEvent instance.
        """
        return cls(
            timestamp=data["timestamp"],
            event_type=data["event_type"],
            function_name=data["function_name"],
            parameters=data["parameters"],
            result=data["result"],
            agent_id=data.get("agent_id"),
            rule_id=data.get("rule_id"),
            context=data.get("context"),
            approved_by=data.get("approved_by"),
            reason=data.get("reason"),
            duration_ms=data.get("duration_ms", 0.0),
            action_id=data.get("action_id"),
            metadata=data.get("metadata", {}),
        )
