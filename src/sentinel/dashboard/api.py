"""REST API for Sentinel Dashboard.

This module provides the FastAPI endpoints that the Sentinel agent
communicates with for approval requests and status polling.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from sentinel.dashboard.state import PendingApproval, get_state_manager

logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Sentinel Dashboard API",
    description="API for AI Agent Governance - Approval Management",
    version="0.1.0",
)

# Add CORS middleware for browser access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ApprovalRequestPayload(BaseModel):
    """Payload for incoming approval requests from Sentinel."""

    action_id: str
    function_name: str
    rule_id: str
    parameters: dict[str, Any]
    reason: str
    agent_id: str | None = None
    context: dict[str, Any] | None = None
    timestamp: str | None = None
    timeout_seconds: float = 300


class ApprovalStatusResponse(BaseModel):
    """Response for approval status queries."""

    action_id: str
    status: str  # pending, approved, denied
    decided_by: str | None = None
    decided_at: str | None = None


class ActionResponse(BaseModel):
    """Response for approve/deny actions."""

    action_id: str
    status: str
    message: str


@app.post("/approval", status_code=202)
async def receive_approval_request(request: ApprovalRequestPayload) -> dict[str, str]:
    """Receive an approval request from Sentinel (webhook endpoint).

    This endpoint is called by the WebhookApprovalInterface when
    an action requires human approval.

    Args:
        request: The approval request payload.

    Returns:
        Acknowledgment with action_id.
    """
    state = get_state_manager()

    # Parse or create timestamp
    if request.timestamp:
        try:
            timestamp = datetime.fromisoformat(request.timestamp)
        except ValueError:
            timestamp = datetime.now(timezone.utc)
    else:
        timestamp = datetime.now(timezone.utc)

    # Calculate timeout
    timeout_at = timestamp + timedelta(seconds=request.timeout_seconds)

    # Create pending approval
    approval = PendingApproval(
        action_id=request.action_id,
        function_name=request.function_name,
        parameters=request.parameters,
        reason=request.reason,
        rule_id=request.rule_id,
        timestamp=timestamp,
        timeout_at=timeout_at,
        agent_id=request.agent_id,
        context=request.context,
    )

    state.add_pending(approval)

    logger.info(f"Received approval request: {request.action_id} for {request.function_name}")

    return {
        "action_id": request.action_id,
        "status": "received",
        "message": "Approval request received and pending review",
    }


@app.get("/approval/{action_id}/status", response_model=ApprovalStatusResponse)
async def get_approval_status(action_id: str) -> ApprovalStatusResponse:
    """Get the status of an approval request.

    This endpoint is polled by the WebhookApprovalInterface to check
    if a decision has been made.

    Args:
        action_id: The unique identifier of the approval request.

    Returns:
        Current status of the approval.

    Raises:
        HTTPException: If action_id not found.
    """
    state = get_state_manager()
    status = state.get_status(action_id)

    if status is None:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")

    return ApprovalStatusResponse(
        action_id=status["action_id"],
        status=status["status"],
        decided_by=status.get("decided_by"),
        decided_at=status.get("decided_at"),
    )


@app.post("/approval/{action_id}/approve", response_model=ActionResponse)
async def approve_action(action_id: str) -> ActionResponse:
    """Approve a pending action.

    Called by the Dashboard UI when user clicks APPROVE.

    Args:
        action_id: The unique identifier of the approval request.

    Returns:
        Confirmation of approval.

    Raises:
        HTTPException: If action_id not found.
    """
    state = get_state_manager()

    if state.approve(action_id, approved_by="dashboard_user"):
        logger.info(f"Action approved via API: {action_id}")
        return ActionResponse(
            action_id=action_id,
            status="approved",
            message="Action approved successfully",
        )
    else:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")


@app.post("/approval/{action_id}/deny", response_model=ActionResponse)
async def deny_action(action_id: str) -> ActionResponse:
    """Deny a pending action.

    Called by the Dashboard UI when user clicks DENY.

    Args:
        action_id: The unique identifier of the approval request.

    Returns:
        Confirmation of denial.

    Raises:
        HTTPException: If action_id not found.
    """
    state = get_state_manager()

    if state.deny(action_id, denied_by="dashboard_user"):
        logger.info(f"Action denied via API: {action_id}")
        return ActionResponse(
            action_id=action_id,
            status="denied",
            message="Action denied",
        )
    else:
        raise HTTPException(status_code=404, detail=f"Action {action_id} not found")


@app.get("/approvals/pending")
async def list_pending_approvals() -> list[dict[str, Any]]:
    """List all pending approval requests.

    Returns:
        List of pending approvals.
    """
    state = get_state_manager()
    pending = state.get_all_pending()
    return [a.to_dict() for a in pending]


@app.get("/approvals/all")
async def list_all_approvals() -> list[dict[str, Any]]:
    """List all approval requests (including decided).

    Returns:
        List of all approvals.
    """
    state = get_state_manager()
    all_approvals = state.get_all()
    return [a.to_dict() for a in all_approvals]


@app.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint.

    Returns:
        Status message.
    """
    return {"status": "healthy", "service": "sentinel-dashboard"}


@app.post("/cleanup")
async def cleanup_old_approvals() -> dict[str, int]:
    """Clean up expired and old approvals.

    Returns:
        Number of items cleaned up.
    """
    state = get_state_manager()
    expired = state.cleanup_expired()
    old = state.cleanup_decided(max_age_hours=24)
    return {"expired_removed": expired, "old_removed": old}
