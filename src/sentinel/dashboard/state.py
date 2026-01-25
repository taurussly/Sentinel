"""State management for pending approvals.

This module provides thread-safe state management for approval requests
that are pending human review via the dashboard.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)


@dataclass
class PendingApproval:
    """A pending approval request.

    Attributes:
        action_id: Unique identifier for this approval request.
        function_name: Name of the function requiring approval.
        parameters: Function parameters.
        reason: Human-readable reason for requiring approval.
        rule_id: ID of the rule that triggered approval.
        timestamp: When the request was created.
        timeout_at: When the request expires.
        agent_id: Optional identifier for the agent.
        context: Optional context from context_fn.
        status: Current status (pending, approved, denied).
        decided_at: When a decision was made.
        decided_by: Who made the decision.
    """

    action_id: str
    function_name: str
    parameters: dict[str, Any]
    reason: str
    rule_id: str
    timestamp: datetime
    timeout_at: datetime
    agent_id: str | None = None
    context: dict[str, Any] | None = None
    status: Literal["pending", "approved", "denied"] = "pending"
    decided_at: datetime | None = None
    decided_by: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        # Convert datetime objects to ISO format strings
        data["timestamp"] = self.timestamp.isoformat()
        data["timeout_at"] = self.timeout_at.isoformat()
        if self.decided_at:
            data["decided_at"] = self.decided_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PendingApproval:
        """Create from dictionary."""
        # Parse datetime strings
        data = data.copy()
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        data["timeout_at"] = datetime.fromisoformat(data["timeout_at"])
        if data.get("decided_at"):
            data["decided_at"] = datetime.fromisoformat(data["decided_at"])
        return cls(**data)

    @property
    def is_expired(self) -> bool:
        """Check if the approval has expired."""
        return datetime.now(timezone.utc) > self.timeout_at.replace(tzinfo=timezone.utc)

    @property
    def remaining_seconds(self) -> float:
        """Get remaining seconds until timeout."""
        now = datetime.now(timezone.utc)
        timeout = self.timeout_at.replace(tzinfo=timezone.utc)
        return max(0, (timeout - now).total_seconds())


class ApprovalStateManager:
    """Thread-safe manager for pending approvals.

    Acts as an in-memory database for the dashboard.
    Persists state to JSON file to survive restarts.

    Attributes:
        state_file: Path to the JSON file for persistence.
    """

    def __init__(self, state_file: Path | str = Path("./sentinel_state.json")):
        """Initialize the state manager.

        Args:
            state_file: Path to the JSON file for persistence.
        """
        self.state_file = Path(state_file)
        self._pending: dict[str, PendingApproval] = {}
        self._lock = threading.Lock()
        self._load_state()

    def _load_state(self) -> None:
        """Load state from file if exists."""
        if self.state_file.exists():
            try:
                with open(self.state_file) as f:
                    data = json.load(f)

                self._pending = {}  # Clear existing state before loading
                for item in data.get("pending", []):
                    approval = PendingApproval.from_dict(item)
                    self._pending[approval.action_id] = approval

                logger.debug(f"Loaded {len(self._pending)} pending approvals from state file")
            except Exception as e:
                logger.error(f"Error loading state file: {e}")
                self._pending = {}

    def _reload_if_needed(self) -> None:
        """Reload state from file to sync with other processes.

        This is needed because FastAPI and Streamlit run in separate
        processes, so they each have their own in-memory state.
        The file is the shared state between them.
        """
        self._load_state()

    def _save_state(self) -> None:
        """Save state to file."""
        try:
            # Ensure directory exists
            self.state_file.parent.mkdir(parents=True, exist_ok=True)

            data = {
                "pending": [a.to_dict() for a in self._pending.values()],
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }

            with open(self.state_file, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving state file: {e}")

    def add_pending(self, approval: PendingApproval) -> None:
        """Add a new pending approval.

        Args:
            approval: The approval to add.
        """
        with self._lock:
            self._pending[approval.action_id] = approval
            self._save_state()
            logger.info(f"Added pending approval: {approval.action_id}")

    def approve(self, action_id: str, approved_by: str = "dashboard_user") -> bool:
        """Approve an action.

        Args:
            action_id: ID of the action to approve.
            approved_by: Who approved the action.

        Returns:
            True if found and approved, False if not found.
        """
        with self._lock:
            self._reload_if_needed()
            if action_id not in self._pending:
                return False

            approval = self._pending[action_id]
            approval.status = "approved"
            approval.decided_at = datetime.now(timezone.utc)
            approval.decided_by = approved_by
            self._save_state()
            logger.info(f"Approved action: {action_id} by {approved_by}")
            return True

    def deny(self, action_id: str, denied_by: str = "dashboard_user") -> bool:
        """Deny an action.

        Args:
            action_id: ID of the action to deny.
            denied_by: Who denied the action.

        Returns:
            True if found and denied, False if not found.
        """
        with self._lock:
            self._reload_if_needed()
            if action_id not in self._pending:
                return False

            approval = self._pending[action_id]
            approval.status = "denied"
            approval.decided_at = datetime.now(timezone.utc)
            approval.decided_by = denied_by
            self._save_state()
            logger.info(f"Denied action: {action_id} by {denied_by}")
            return True

    def get_status(self, action_id: str) -> dict[str, Any] | None:
        """Get the status of an action.

        Args:
            action_id: ID of the action.

        Returns:
            Status dict if found, None if not found.
        """
        with self._lock:
            self._reload_if_needed()
            if action_id not in self._pending:
                return None

            approval = self._pending[action_id]
            return {
                "action_id": action_id,
                "status": approval.status,
                "decided_by": approval.decided_by,
                "decided_at": approval.decided_at.isoformat() if approval.decided_at else None,
            }

    def get_all_pending(self) -> list[PendingApproval]:
        """Get all pending approvals (status == 'pending').

        Returns:
            List of pending approvals sorted by timestamp (oldest first).
        """
        with self._lock:
            self._reload_if_needed()
            pending = [
                a for a in self._pending.values()
                if a.status == "pending" and not a.is_expired
            ]
            return sorted(pending, key=lambda a: a.timestamp)

    def get_all(self) -> list[PendingApproval]:
        """Get all approvals (including decided ones).

        Returns:
            List of all approvals sorted by timestamp (newest first).
        """
        with self._lock:
            self._reload_if_needed()
            return sorted(self._pending.values(), key=lambda a: a.timestamp, reverse=True)

    def cleanup_expired(self) -> int:
        """Remove expired approvals that are still pending.

        Returns:
            Number of approvals removed.
        """
        with self._lock:
            self._reload_if_needed()
            expired = [
                action_id for action_id, approval in self._pending.items()
                if approval.status == "pending" and approval.is_expired
            ]

            for action_id in expired:
                del self._pending[action_id]

            if expired:
                self._save_state()
                logger.info(f"Cleaned up {len(expired)} expired approvals")

            return len(expired)

    def cleanup_decided(self, max_age_hours: int = 24) -> int:
        """Remove old decided approvals.

        Args:
            max_age_hours: Maximum age in hours for decided approvals.

        Returns:
            Number of approvals removed.
        """
        with self._lock:
            self._reload_if_needed()
            cutoff = datetime.now(timezone.utc)
            old = []

            for action_id, approval in self._pending.items():
                if approval.status != "pending" and approval.decided_at:
                    decided_at = approval.decided_at.replace(tzinfo=timezone.utc)
                    age_hours = (cutoff - decided_at).total_seconds() / 3600
                    if age_hours > max_age_hours:
                        old.append(action_id)

            for action_id in old:
                del self._pending[action_id]

            if old:
                self._save_state()
                logger.info(f"Cleaned up {len(old)} old decided approvals")

            return len(old)

    def count_by_status(self) -> dict[str, int]:
        """Count approvals by status.

        Returns:
            Dict with counts for each status.
        """
        with self._lock:
            self._reload_if_needed()
            counts = {"pending": 0, "approved": 0, "denied": 0, "expired": 0}

            for approval in self._pending.values():
                if approval.status == "pending" and approval.is_expired:
                    counts["expired"] += 1
                else:
                    counts[approval.status] += 1

            return counts


# Global state manager instance (singleton pattern)
_state_manager: ApprovalStateManager | None = None


def get_state_manager(state_file: Path | str | None = None) -> ApprovalStateManager:
    """Get or create the global state manager.

    Args:
        state_file: Optional path to state file. Only used on first call.

    Returns:
        The global ApprovalStateManager instance.
    """
    global _state_manager

    if _state_manager is None:
        _state_manager = ApprovalStateManager(
            state_file=state_file or Path("./sentinel_state.json")
        )

    return _state_manager
