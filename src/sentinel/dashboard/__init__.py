"""Sentinel Dashboard - Command Center for AI Agent Governance.

This module provides a web-based dashboard for:
- Viewing audit logs and action history
- Approving/denying pending actions in real-time
- Monitoring metrics and value protected

Usage:
    python -m sentinel.dashboard
"""

from sentinel.dashboard.state import ApprovalStateManager, PendingApproval

__all__ = ["ApprovalStateManager", "PendingApproval"]
