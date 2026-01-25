"""Mock webhook server for testing the WebhookApprovalInterface.

This module provides utilities for testing webhook-based approval flows
without requiring a real HTTP server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class MockApprovalState:
    """State manager for mock approval responses.

    This class simulates a backend that receives approval requests
    and allows controlling the approval status for testing.
    """

    # Storage for received requests
    requests: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Controlled responses for status polling
    responses: dict[str, str] = field(default_factory=dict)

    # Approver info
    approvers: dict[str, str] = field(default_factory=dict)

    # Denial reasons
    reasons: dict[str, str] = field(default_factory=dict)

    def receive_request(self, action_id: str, payload: dict[str, Any]) -> None:
        """Store a received approval request.

        Args:
            action_id: The action ID.
            payload: The request payload.
        """
        self.requests[action_id] = payload
        # Default to pending
        if action_id not in self.responses:
            self.responses[action_id] = "pending"

    def approve(self, action_id: str, approved_by: str = "test@example.com") -> None:
        """Approve an action.

        Args:
            action_id: The action ID to approve.
            approved_by: Who approved it.
        """
        self.responses[action_id] = "approved"
        self.approvers[action_id] = approved_by

    def deny(
        self, action_id: str, reason: str = "Denied", approved_by: str = "admin@example.com"
    ) -> None:
        """Deny an action.

        Args:
            action_id: The action ID to deny.
            reason: Reason for denial.
            approved_by: Who denied it.
        """
        self.responses[action_id] = "denied"
        self.approvers[action_id] = approved_by
        self.reasons[action_id] = reason

    def get_status(self, action_id: str) -> dict[str, Any]:
        """Get the status response for an action.

        Args:
            action_id: The action ID.

        Returns:
            Status response dict.
        """
        status = self.responses.get(action_id, "pending")
        response: dict[str, Any] = {
            "action_id": action_id,
            "status": status,
        }

        if status in ("approved", "denied"):
            response["approved_by"] = self.approvers.get(action_id)
            response["approved_at"] = datetime.now(timezone.utc).isoformat()

        if status == "denied" and action_id in self.reasons:
            response["reason"] = self.reasons[action_id]

        return response

    def reset(self) -> None:
        """Reset all state."""
        self.requests.clear()
        self.responses.clear()
        self.approvers.clear()
        self.reasons.clear()


def create_webhook_response(status_code: int = 202) -> dict[str, Any]:
    """Create a mock webhook POST response.

    Args:
        status_code: The HTTP status code (not used in body, just for reference).

    Returns:
        Response body dict.
    """
    return {"status": "received", "message": "Approval request queued"}


def create_status_response(
    action_id: str,
    status: str = "pending",
    approved_by: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Create a mock status polling response.

    Args:
        action_id: The action ID.
        status: The approval status (pending, approved, denied).
        approved_by: Who made the decision.
        reason: Reason for denial (if denied).

    Returns:
        Response body dict.
    """
    response: dict[str, Any] = {
        "action_id": action_id,
        "status": status,
    }

    if status in ("approved", "denied"):
        response["approved_by"] = approved_by or "system"
        response["approved_at"] = datetime.now(timezone.utc).isoformat()

    if reason:
        response["reason"] = reason

    return response
