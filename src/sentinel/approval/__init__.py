"""Approval module for Sentinel.

This module provides approval interfaces for requesting
human approval of agent actions.
"""

from sentinel.approval.base import (
    ApprovalInterface,
    ApprovalRequest,
    ApprovalResult,
    ApprovalStatus,
)
from sentinel.approval.terminal import TerminalApprovalInterface
from sentinel.approval.webhook import WebhookApprovalInterface, WebhookConfig

__all__ = [
    "ApprovalInterface",
    "ApprovalRequest",
    "ApprovalResult",
    "ApprovalStatus",
    "TerminalApprovalInterface",
    "WebhookApprovalInterface",
    "WebhookConfig",
]
