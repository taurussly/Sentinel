"""Tests for the Sentinel approval interfaces."""

import pytest
from unittest.mock import AsyncMock, patch
from typing import Any

from sentinel.approval.base import (
    ApprovalInterface,
    ApprovalResult,
    ApprovalStatus,
    ApprovalRequest,
)
from sentinel.approval.terminal import TerminalApprovalInterface


class TestApprovalRequest:
    """Tests for ApprovalRequest model."""

    def test_approval_request_creation(self) -> None:
        """Test creating an approval request."""
        request = ApprovalRequest(
            action_id="test-123",
            function_name="transfer_funds",
            parameters={"amount": 150, "destination": "user@example.com"},
            rule_id="financial_limit",
            message="Transfer above $100 requires approval",
        )
        assert request.action_id == "test-123"
        assert request.function_name == "transfer_funds"
        assert request.parameters["amount"] == 150
        assert request.rule_id == "financial_limit"

    def test_approval_request_auto_generates_id(self) -> None:
        """Test that action_id is auto-generated if not provided."""
        request = ApprovalRequest(
            function_name="transfer_funds",
            parameters={"amount": 150},
            rule_id="financial_limit",
            message="Requires approval",
        )
        assert request.action_id is not None
        assert len(request.action_id) > 0


class TestApprovalResult:
    """Tests for ApprovalResult model."""

    def test_approval_result_approved(self) -> None:
        """Test approved result."""
        result = ApprovalResult(
            status=ApprovalStatus.APPROVED,
            action_id="test-123",
            approved_by="user@example.com",
            reason="Looks good",
        )
        assert result.is_approved is True
        assert result.is_denied is False
        assert result.is_timeout is False

    def test_approval_result_denied(self) -> None:
        """Test denied result."""
        result = ApprovalResult(
            status=ApprovalStatus.DENIED,
            action_id="test-123",
            approved_by="admin@example.com",
            reason="Too expensive",
        )
        assert result.is_approved is False
        assert result.is_denied is True
        assert result.is_timeout is False

    def test_approval_result_timeout(self) -> None:
        """Test timeout result."""
        result = ApprovalResult(
            status=ApprovalStatus.TIMEOUT,
            action_id="test-123",
        )
        assert result.is_approved is False
        assert result.is_denied is False
        assert result.is_timeout is True


class TestApprovalInterface:
    """Tests for the abstract ApprovalInterface."""

    def test_cannot_instantiate_abstract_class(self) -> None:
        """Test that ApprovalInterface cannot be instantiated directly."""
        with pytest.raises(TypeError):
            ApprovalInterface()  # type: ignore


class TestTerminalApprovalInterface:
    """Tests for the terminal approval interface."""

    @pytest.fixture
    def interface(self) -> TerminalApprovalInterface:
        """Create a terminal approval interface for testing."""
        return TerminalApprovalInterface(timeout_seconds=30)

    @pytest.fixture
    def sample_request(self) -> ApprovalRequest:
        """Create a sample approval request."""
        return ApprovalRequest(
            action_id="test-123",
            function_name="transfer_funds",
            parameters={"amount": 150, "destination": "user@example.com"},
            rule_id="financial_limit",
            message="Transfer above $100 requires approval",
        )

    async def test_request_approval_approved(
        self, interface: TerminalApprovalInterface, sample_request: ApprovalRequest
    ) -> None:
        """Test approval flow when user approves."""
        with patch.object(interface, "_get_user_input", return_value="y"):
            result = await interface.request_approval(sample_request)

        assert result.status == ApprovalStatus.APPROVED
        assert result.action_id == "test-123"

    async def test_request_approval_denied(
        self, interface: TerminalApprovalInterface, sample_request: ApprovalRequest
    ) -> None:
        """Test approval flow when user denies."""
        with patch.object(interface, "_get_user_input", return_value="n"):
            result = await interface.request_approval(sample_request)

        assert result.status == ApprovalStatus.DENIED
        assert result.action_id == "test-123"

    async def test_request_approval_accepts_yes_variations(
        self, interface: TerminalApprovalInterface, sample_request: ApprovalRequest
    ) -> None:
        """Test that various 'yes' inputs are accepted."""
        for yes_input in ["y", "Y", "yes", "YES", "Yes"]:
            with patch.object(interface, "_get_user_input", return_value=yes_input):
                result = await interface.request_approval(sample_request)
            assert result.status == ApprovalStatus.APPROVED

    async def test_request_approval_accepts_no_variations(
        self, interface: TerminalApprovalInterface, sample_request: ApprovalRequest
    ) -> None:
        """Test that various 'no' inputs are accepted."""
        for no_input in ["n", "N", "no", "NO", "No"]:
            with patch.object(interface, "_get_user_input", return_value=no_input):
                result = await interface.request_approval(sample_request)
            assert result.status == ApprovalStatus.DENIED

    async def test_request_approval_invalid_input_retries(
        self, interface: TerminalApprovalInterface, sample_request: ApprovalRequest
    ) -> None:
        """Test that invalid input causes retry."""
        call_count = 0
        responses = ["invalid", "maybe", "y"]

        def mock_input() -> str:
            nonlocal call_count
            result = responses[call_count]
            call_count += 1
            return result

        with patch.object(interface, "_get_user_input", side_effect=mock_input):
            result = await interface.request_approval(sample_request)

        assert result.status == ApprovalStatus.APPROVED
        assert call_count == 3

    async def test_request_approval_timeout(
        self, sample_request: ApprovalRequest
    ) -> None:
        """Test approval timeout behavior."""
        interface = TerminalApprovalInterface(timeout_seconds=0.1)

        async def slow_input() -> str:
            import asyncio
            await asyncio.sleep(1)
            return "y"

        with patch.object(interface, "_get_user_input_async", side_effect=slow_input):
            result = await interface.request_approval(sample_request)

        assert result.status == ApprovalStatus.TIMEOUT

    def test_format_request_display(
        self, interface: TerminalApprovalInterface, sample_request: ApprovalRequest
    ) -> None:
        """Test that request is formatted correctly for display."""
        display = interface.format_request(sample_request)

        assert "transfer_funds" in display
        assert "amount" in display
        assert "150" in display
        assert "Transfer above $100 requires approval" in display

    def test_format_request_with_context(
        self, interface: TerminalApprovalInterface
    ) -> None:
        """Test that context is displayed in formatted output."""
        request = ApprovalRequest(
            action_id="test-456",
            function_name="transfer_funds",
            parameters={"amount": 500},
            rule_id="financial_limit",
            message="Requires approval",
            context={
                "current_balance": 1000.0,
                "daily_limit": 5000.0,
                "user_email": "test@example.com",
            },
        )

        display = interface.format_request(request)

        # Context section should be present
        assert "Context:" in display
        assert "current_balance" in display
        assert "1000.0" in display
        assert "daily_limit" in display
        assert "5000.0" in display
        assert "user_email" in display
        assert "test@example.com" in display

    def test_format_request_without_context(
        self, interface: TerminalApprovalInterface
    ) -> None:
        """Test that format works when context is None."""
        request = ApprovalRequest(
            action_id="test-789",
            function_name="read_data",
            parameters={"id": 123},
            rule_id="some_rule",
            message="Requires approval",
            context=None,
        )

        display = interface.format_request(request)

        # Should NOT have Context section
        assert "Context:" not in display
        # But should have other fields
        assert "read_data" in display
        assert "123" in display

    def test_terminal_interface_with_custom_timeout(self) -> None:
        """Test creating interface with custom timeout."""
        interface = TerminalApprovalInterface(timeout_seconds=60)
        assert interface.timeout_seconds == 60

    def test_terminal_interface_default_timeout(self) -> None:
        """Test default timeout value."""
        interface = TerminalApprovalInterface()
        assert interface.timeout_seconds == 300  # 5 minutes default


class TestApprovalInterfaceContract:
    """Contract tests that any ApprovalInterface implementation must pass."""

    @pytest.fixture(params=["terminal"])
    def interface(self, request: Any) -> ApprovalInterface:
        """Parameterized fixture for all approval interface implementations."""
        if request.param == "terminal":
            return TerminalApprovalInterface(timeout_seconds=30)
        raise ValueError(f"Unknown interface: {request.param}")

    async def test_interface_returns_approval_result(
        self, interface: ApprovalInterface
    ) -> None:
        """Test that interface returns an ApprovalResult."""
        request = ApprovalRequest(
            function_name="test_function",
            parameters={},
            rule_id="test_rule",
            message="Test message",
        )

        with patch.object(interface, "_get_user_input", return_value="y"):
            result = await interface.request_approval(request)

        assert isinstance(result, ApprovalResult)

    async def test_interface_preserves_action_id(
        self, interface: ApprovalInterface
    ) -> None:
        """Test that interface preserves the action_id in the result."""
        request = ApprovalRequest(
            action_id="unique-id-12345",
            function_name="test_function",
            parameters={},
            rule_id="test_rule",
            message="Test message",
        )

        with patch.object(interface, "_get_user_input", return_value="n"):
            result = await interface.request_approval(request)

        assert result.action_id == "unique-id-12345"
