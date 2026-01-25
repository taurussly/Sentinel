"""Tests for the Sentinel Dashboard.

Tests the state management and API endpoints.
"""

import json
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinel.dashboard.state import ApprovalStateManager, PendingApproval


class TestPendingApproval:
    """Tests for PendingApproval model."""

    def test_create_pending_approval(self):
        """Test creating a pending approval."""
        now = datetime.now(timezone.utc)
        approval = PendingApproval(
            action_id="test-123",
            function_name="transfer_funds",
            parameters={"amount": 500},
            reason="Amount exceeds threshold",
            rule_id="financial_limit",
            timestamp=now,
            timeout_at=now + timedelta(seconds=300),
            agent_id="test-agent",
        )

        assert approval.action_id == "test-123"
        assert approval.function_name == "transfer_funds"
        assert approval.status == "pending"
        assert approval.agent_id == "test-agent"

    def test_to_dict(self):
        """Test converting approval to dict."""
        now = datetime.now(timezone.utc)
        approval = PendingApproval(
            action_id="test-456",
            function_name="delete_user",
            parameters={"user_id": 123},
            reason="Delete requires approval",
            rule_id="block_delete",
            timestamp=now,
            timeout_at=now + timedelta(seconds=60),
            context={"extra_info": "value"},
        )

        data = approval.to_dict()

        assert data["action_id"] == "test-456"
        assert data["function_name"] == "delete_user"
        assert data["parameters"] == {"user_id": 123}
        assert data["context"] == {"extra_info": "value"}
        assert "timestamp" in data

    def test_from_dict(self):
        """Test creating approval from dict."""
        now = datetime.now(timezone.utc)
        data = {
            "action_id": "test-789",
            "function_name": "send_email",
            "parameters": {"to": "user@example.com"},
            "reason": "Email requires approval",
            "rule_id": "email_rule",
            "timestamp": now.isoformat(),
            "timeout_at": (now + timedelta(seconds=120)).isoformat(),
            "agent_id": "email-agent",
            "context": None,
            "status": "pending",
            "decided_at": None,
            "decided_by": None,
        }

        approval = PendingApproval.from_dict(data)

        assert approval.action_id == "test-789"
        assert approval.function_name == "send_email"
        assert approval.agent_id == "email-agent"

    def test_is_expired(self):
        """Test expiration check."""
        now = datetime.now(timezone.utc)

        # Not expired
        approval1 = PendingApproval(
            action_id="test-1",
            function_name="func",
            parameters={},
            reason="test",
            rule_id="rule",
            timestamp=now,
            timeout_at=now + timedelta(seconds=300),
        )
        assert not approval1.is_expired

        # Expired
        approval2 = PendingApproval(
            action_id="test-2",
            function_name="func",
            parameters={},
            reason="test",
            rule_id="rule",
            timestamp=now - timedelta(seconds=400),
            timeout_at=now - timedelta(seconds=100),
        )
        assert approval2.is_expired

    def test_remaining_seconds(self):
        """Test remaining seconds calculation."""
        now = datetime.now(timezone.utc)
        approval = PendingApproval(
            action_id="test",
            function_name="func",
            parameters={},
            reason="test",
            rule_id="rule",
            timestamp=now,
            timeout_at=now + timedelta(seconds=60),
        )

        remaining = approval.remaining_seconds
        assert 55 <= remaining <= 60  # Allow some tolerance


class TestApprovalStateManager:
    """Tests for ApprovalStateManager."""

    @pytest.fixture
    def state_file(self, tmp_path):
        """Create temporary state file."""
        return tmp_path / "test_state.json"

    @pytest.fixture
    def manager(self, state_file):
        """Create state manager with temporary file."""
        return ApprovalStateManager(state_file=state_file)

    def test_add_pending(self, manager):
        """Test adding a pending approval."""
        now = datetime.now(timezone.utc)
        approval = PendingApproval(
            action_id="add-test",
            function_name="test_func",
            parameters={"key": "value"},
            reason="Test reason",
            rule_id="test_rule",
            timestamp=now,
            timeout_at=now + timedelta(seconds=300),
        )

        manager.add_pending(approval)

        # Verify it was added
        pending = manager.get_all_pending()
        assert len(pending) == 1
        assert pending[0].action_id == "add-test"

    def test_approve(self, manager):
        """Test approving an action."""
        now = datetime.now(timezone.utc)
        approval = PendingApproval(
            action_id="approve-test",
            function_name="test_func",
            parameters={},
            reason="Test",
            rule_id="rule",
            timestamp=now,
            timeout_at=now + timedelta(seconds=300),
        )
        manager.add_pending(approval)

        # Approve
        result = manager.approve("approve-test", approved_by="tester")

        assert result is True

        # Check status
        status = manager.get_status("approve-test")
        assert status["status"] == "approved"
        assert status["decided_by"] == "tester"

    def test_deny(self, manager):
        """Test denying an action."""
        now = datetime.now(timezone.utc)
        approval = PendingApproval(
            action_id="deny-test",
            function_name="test_func",
            parameters={},
            reason="Test",
            rule_id="rule",
            timestamp=now,
            timeout_at=now + timedelta(seconds=300),
        )
        manager.add_pending(approval)

        # Deny
        result = manager.deny("deny-test", denied_by="tester")

        assert result is True

        # Check status
        status = manager.get_status("deny-test")
        assert status["status"] == "denied"
        assert status["decided_by"] == "tester"

    def test_get_status_not_found(self, manager):
        """Test getting status for non-existent action."""
        status = manager.get_status("non-existent")
        assert status is None

    def test_approve_not_found(self, manager):
        """Test approving non-existent action."""
        result = manager.approve("non-existent")
        assert result is False

    def test_get_all_pending_excludes_decided(self, manager):
        """Test that get_all_pending excludes decided approvals."""
        now = datetime.now(timezone.utc)

        # Add pending
        manager.add_pending(PendingApproval(
            action_id="pending-1",
            function_name="func",
            parameters={},
            reason="test",
            rule_id="rule",
            timestamp=now,
            timeout_at=now + timedelta(seconds=300),
        ))

        # Add and approve
        manager.add_pending(PendingApproval(
            action_id="approved-1",
            function_name="func",
            parameters={},
            reason="test",
            rule_id="rule",
            timestamp=now,
            timeout_at=now + timedelta(seconds=300),
        ))
        manager.approve("approved-1")

        # Get pending
        pending = manager.get_all_pending()
        assert len(pending) == 1
        assert pending[0].action_id == "pending-1"

    def test_persistence(self, state_file):
        """Test that state is persisted to file."""
        now = datetime.now(timezone.utc)

        # Create manager and add approval
        manager1 = ApprovalStateManager(state_file=state_file)
        manager1.add_pending(PendingApproval(
            action_id="persist-test",
            function_name="func",
            parameters={"data": 123},
            reason="test",
            rule_id="rule",
            timestamp=now,
            timeout_at=now + timedelta(seconds=300),
        ))

        # Create new manager with same file
        manager2 = ApprovalStateManager(state_file=state_file)

        # Should load the approval
        pending = manager2.get_all_pending()
        assert len(pending) == 1
        assert pending[0].action_id == "persist-test"

    def test_count_by_status(self, manager):
        """Test counting by status."""
        now = datetime.now(timezone.utc)

        # Add various approvals
        manager.add_pending(PendingApproval(
            action_id="p1", function_name="f", parameters={},
            reason="r", rule_id="r", timestamp=now,
            timeout_at=now + timedelta(seconds=300),
        ))
        manager.add_pending(PendingApproval(
            action_id="p2", function_name="f", parameters={},
            reason="r", rule_id="r", timestamp=now,
            timeout_at=now + timedelta(seconds=300),
        ))
        manager.add_pending(PendingApproval(
            action_id="a1", function_name="f", parameters={},
            reason="r", rule_id="r", timestamp=now,
            timeout_at=now + timedelta(seconds=300),
        ))
        manager.approve("a1")

        counts = manager.count_by_status()

        assert counts["pending"] == 2
        assert counts["approved"] == 1
        assert counts["denied"] == 0


# Skip API tests if fastapi/httpx not installed
try:
    from fastapi.testclient import TestClient
    from sentinel.dashboard.api import app
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="fastapi not installed")
class TestDashboardAPI:
    """Tests for the Dashboard API endpoints."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        return TestClient(app)

    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"

    def test_receive_approval_request(self, client):
        """Test receiving an approval request."""
        payload = {
            "action_id": "api-test-123",
            "function_name": "transfer_funds",
            "rule_id": "financial_limit",
            "parameters": {"amount": 500},
            "reason": "Amount exceeds threshold",
            "agent_id": "test-agent",
            "timeout_seconds": 300,
        }

        response = client.post("/approval", json=payload)

        assert response.status_code == 202
        data = response.json()
        assert data["action_id"] == "api-test-123"
        assert data["status"] == "received"

    def test_get_approval_status(self, client):
        """Test getting approval status."""
        # First, add an approval
        payload = {
            "action_id": "status-test-456",
            "function_name": "test_func",
            "rule_id": "rule",
            "parameters": {},
            "reason": "test",
            "timeout_seconds": 300,
        }
        client.post("/approval", json=payload)

        # Get status
        response = client.get("/approval/status-test-456/status")

        assert response.status_code == 200
        data = response.json()
        assert data["action_id"] == "status-test-456"
        assert data["status"] == "pending"

    def test_approve_action(self, client):
        """Test approving via API."""
        # Add approval
        payload = {
            "action_id": "approve-api-test",
            "function_name": "func",
            "rule_id": "rule",
            "parameters": {},
            "reason": "test",
            "timeout_seconds": 300,
        }
        client.post("/approval", json=payload)

        # Approve
        response = client.post("/approval/approve-api-test/approve")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "approved"

        # Verify status changed
        status_response = client.get("/approval/approve-api-test/status")
        assert status_response.json()["status"] == "approved"

    def test_deny_action(self, client):
        """Test denying via API."""
        # Add approval
        payload = {
            "action_id": "deny-api-test",
            "function_name": "func",
            "rule_id": "rule",
            "parameters": {},
            "reason": "test",
            "timeout_seconds": 300,
        }
        client.post("/approval", json=payload)

        # Deny
        response = client.post("/approval/deny-api-test/deny")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "denied"

    def test_list_pending(self, client):
        """Test listing pending approvals."""
        # Add approvals
        for i in range(3):
            payload = {
                "action_id": f"list-test-{i}",
                "function_name": "func",
                "rule_id": "rule",
                "parameters": {},
                "reason": "test",
                "timeout_seconds": 300,
            }
            client.post("/approval", json=payload)

        # List pending
        response = client.get("/approvals/pending")

        assert response.status_code == 200
        data = response.json()
        assert len(data) >= 3

    def test_status_not_found(self, client):
        """Test getting status for non-existent action."""
        response = client.get("/approval/non-existent-id/status")
        assert response.status_code == 404
