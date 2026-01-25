"""Tests for context_fn functionality.

Tests that context_fn is properly called when approval is required,
and that context is passed to the approval interface.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock

from sentinel import SentinelConfig, protect
from sentinel.approval.base import (
    ApprovalInterface,
    ApprovalRequest,
    ApprovalResult,
    ApprovalStatus,
)
from sentinel.core.wrapper import clear_wrapper_cache


class MockApprovalInterface(ApprovalInterface):
    """Mock approval interface for testing."""

    def __init__(self):
        self.last_request: ApprovalRequest | None = None
        self.response_status = ApprovalStatus.APPROVED

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        self.last_request = request
        return ApprovalResult(
            status=self.response_status,
            action_id=request.action_id or "test-id",
            approved_by="test-user",
        )


@pytest.fixture
def mock_approval():
    """Create a mock approval interface."""
    return MockApprovalInterface()


@pytest.fixture
def config(tmp_path, mock_approval):
    """Create test config with rules that require approval."""
    rules_file = tmp_path / "rules.json"
    rules_file.write_text("""
    {
        "version": "1.0",
        "default_action": "allow",
        "rules": [
            {
                "id": "require_approval",
                "name": "Require approval for transfers",
                "function_pattern": "transfer_*",
                "conditions": [{"param": "amount", "operator": "gt", "value": 100}],
                "action": "require_approval",
                "priority": 10,
                "message": "Transfer requires approval"
            }
        ]
    }
    """)

    clear_wrapper_cache()
    return SentinelConfig(
        rules_path=rules_file,
        approval_interface=mock_approval,
        fail_mode="secure",
    )


class TestContextFn:
    """Tests for context_fn parameter."""

    @pytest.mark.asyncio
    async def test_context_fn_called_when_approval_required(self, config, mock_approval):
        """Test that context_fn is called when approval is required."""
        context_fn_called = False

        def get_context():
            nonlocal context_fn_called
            context_fn_called = True
            return {"balance": 1000, "user": "test@example.com"}

        @protect(config, context_fn=get_context)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount} to {destination}"

        result = await transfer_funds(500.0, "user@example.com")

        assert context_fn_called
        assert result == "Transferred $500.0 to user@example.com"

    @pytest.mark.asyncio
    async def test_context_fn_not_called_when_allowed(self, tmp_path, mock_approval):
        """Test that context_fn is NOT called when action is allowed."""
        rules_file = tmp_path / "rules_allow.json"
        rules_file.write_text("""
        {
            "version": "1.0",
            "default_action": "allow",
            "rules": []
        }
        """)

        clear_wrapper_cache()
        allow_config = SentinelConfig(
            rules_path=rules_file,
            approval_interface=mock_approval,
            fail_mode="secure",
        )

        context_fn_called = False

        def get_context():
            nonlocal context_fn_called
            context_fn_called = True
            return {"balance": 1000}

        @protect(allow_config, context_fn=get_context)
        async def read_data(data_id: int) -> str:
            return f"Data for {data_id}"

        result = await read_data(123)

        assert not context_fn_called  # Should NOT be called
        assert result == "Data for 123"

    @pytest.mark.asyncio
    async def test_context_passed_to_approval_request(self, config, mock_approval):
        """Test that context is passed to the approval request."""

        def get_context():
            return {
                "account_balance": "$5000",
                "daily_limit": "$1000",
                "transfers_today": "$200",
            }

        @protect(config, context_fn=get_context)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount}"

        await transfer_funds(500.0, "user@example.com")

        assert mock_approval.last_request is not None
        assert mock_approval.last_request.context is not None
        assert mock_approval.last_request.context["account_balance"] == "$5000"
        assert mock_approval.last_request.context["daily_limit"] == "$1000"
        assert mock_approval.last_request.context["transfers_today"] == "$200"

    @pytest.mark.asyncio
    async def test_context_fn_error_handled_gracefully(self, config, mock_approval):
        """Test that errors in context_fn are handled gracefully."""

        def get_context():
            raise RuntimeError("Context error")

        @protect(config, context_fn=get_context)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount}"

        # Should not raise, but context should be None
        result = await transfer_funds(500.0, "user@example.com")

        assert result == "Transferred $500.0"
        assert mock_approval.last_request is not None
        assert mock_approval.last_request.context is None  # Error => None

    @pytest.mark.asyncio
    async def test_context_fn_with_none(self, config, mock_approval):
        """Test that None context_fn works correctly."""

        @protect(config, context_fn=None)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount}"

        result = await transfer_funds(500.0, "user@example.com")

        assert result == "Transferred $500.0"
        assert mock_approval.last_request is not None
        assert mock_approval.last_request.context is None

    def test_context_fn_sync_function(self, config, mock_approval):
        """Test context_fn with synchronous function."""
        context_fn_called = False

        def get_context():
            nonlocal context_fn_called
            context_fn_called = True
            return {"sync": True, "value": 42}

        @protect(config, context_fn=get_context)
        def transfer_funds_sync(amount: float, destination: str) -> str:
            return f"Transferred ${amount} to {destination}"

        result = transfer_funds_sync(500.0, "user@example.com")

        assert context_fn_called
        assert result == "Transferred $500.0 to user@example.com"
        assert mock_approval.last_request.context["sync"] is True
        assert mock_approval.last_request.context["value"] == 42


class TestContextDisplay:
    """Tests for context display in approval requests."""

    @pytest.mark.asyncio
    async def test_format_request_includes_context(self, config, mock_approval):
        """Test that format_request includes context in output."""

        def get_context():
            return {"important_info": "value123"}

        @protect(config, context_fn=get_context)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount}"

        await transfer_funds(500.0, "user@example.com")

        # Format the request and check context is included
        formatted = mock_approval.format_request(mock_approval.last_request)

        assert "Context:" in formatted
        assert "important_info" in formatted
        assert "value123" in formatted

    @pytest.mark.asyncio
    async def test_format_request_no_context(self, config, mock_approval):
        """Test that format_request works without context."""

        @protect(config, context_fn=None)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount}"

        await transfer_funds(500.0, "user@example.com")

        formatted = mock_approval.format_request(mock_approval.last_request)

        assert "Context:" not in formatted  # No context section


class TestContextWithWebhook:
    """Tests for context with webhook approval."""

    @pytest.mark.asyncio
    async def test_context_included_in_webhook_payload(self, tmp_path):
        """Test that context is included in webhook payload."""
        from sentinel.approval.webhook import WebhookApprovalInterface

        rules_file = tmp_path / "rules.json"
        rules_file.write_text("""
        {
            "version": "1.0",
            "default_action": "allow",
            "rules": [
                {
                    "id": "require_approval",
                    "name": "Require approval",
                    "function_pattern": "transfer_*",
                    "conditions": [{"param": "amount", "operator": "gt", "value": 100}],
                    "action": "require_approval",
                    "priority": 10,
                    "message": "Approval required"
                }
            ]
        }
        """)

        webhook = WebhookApprovalInterface(
            webhook_url="https://example.com/webhook",
            status_url_template="https://example.com/status/{action_id}",
            token="test-token",
            timeout_seconds=1,
        )

        # Test _build_payload method
        from sentinel.approval.base import ApprovalRequest

        request = ApprovalRequest(
            function_name="transfer_funds",
            parameters={"amount": 500, "destination": "user@example.com"},
            rule_id="test_rule",
            message="Test message",
            action_id="test-action-id",
            context={"balance": 1000, "user": "test@example.com"},
        )

        payload = webhook._build_payload(request)

        assert "context" in payload
        assert payload["context"]["balance"] == 1000
        assert payload["context"]["user"] == "test@example.com"

        await webhook.close()
