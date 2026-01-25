"""Tests for the Sentinel wrapper/decorator."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path
from typing import Any

from sentinel import protect, SentinelConfig
from sentinel.core.wrapper import SentinelWrapper, clear_wrapper_cache
from sentinel.core.exceptions import (
    SentinelBlockedError,
    SentinelConfigError,
    SentinelTimeoutError,
)
from sentinel.approval.base import ApprovalResult, ApprovalStatus, ApprovalRequest
from sentinel.approval.terminal import TerminalApprovalInterface
from sentinel.rules.engine import RuleAction


FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def clear_cache() -> None:
    """Clear wrapper cache before each test to ensure isolation."""
    clear_wrapper_cache()


class TestSentinelConfig:
    """Tests for SentinelConfig."""

    def test_config_from_rules_path(self) -> None:
        """Test creating config from rules file path."""
        config = SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            approval_interface="terminal",
        )
        assert config.rules_path == FIXTURES_DIR / "sample_rules.json"
        assert config.fail_mode == "secure"  # default

    def test_config_with_fail_safe_mode(self) -> None:
        """Test creating config with fail-safe mode."""
        config = SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            fail_mode="safe",
        )
        assert config.fail_mode == "safe"

    def test_config_with_custom_approval_interface(self) -> None:
        """Test creating config with custom approval interface."""
        custom_interface = TerminalApprovalInterface(timeout_seconds=60)
        config = SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            approval_interface=custom_interface,
        )
        assert config.approval_interface is custom_interface

    def test_config_invalid_rules_path_raises_error(self) -> None:
        """Test that invalid rules path raises error."""
        with pytest.raises(SentinelConfigError):
            SentinelConfig(
                rules_path=Path("/nonexistent/rules.json"),
                approval_interface="terminal",
            )

    def test_config_invalid_fail_mode_raises_error(self) -> None:
        """Test that invalid fail mode raises error."""
        with pytest.raises(ValueError):
            SentinelConfig(
                rules_path=FIXTURES_DIR / "sample_rules.json",
                fail_mode="invalid",  # type: ignore
            )


class TestSentinelWrapper:
    """Tests for the SentinelWrapper class."""

    @pytest.fixture
    def config(self) -> SentinelConfig:
        """Create a test config."""
        return SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            approval_interface="terminal",
        )

    @pytest.fixture
    def wrapper(self, config: SentinelConfig) -> SentinelWrapper:
        """Create a test wrapper."""
        return SentinelWrapper(config)

    def test_wrapper_loads_rules(self, wrapper: SentinelWrapper) -> None:
        """Test that wrapper loads rules from config."""
        assert len(wrapper.rules_engine.rules) > 0


class TestProtectDecoratorAsync:
    """Tests for the @protect decorator with async functions."""

    @pytest.fixture
    def config(self) -> SentinelConfig:
        """Create a test config."""
        return SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            approval_interface="terminal",
        )

    async def test_allows_action_when_no_rules_match(self, config: SentinelConfig) -> None:
        """Test that action is allowed when no rules match."""

        @protect(config)
        async def read_data(data_id: int) -> str:
            return f"Data {data_id}"

        result = await read_data(123)
        assert result == "Data 123"

    async def test_blocks_action_when_block_rule_matches(
        self, config: SentinelConfig
    ) -> None:
        """Test that action is blocked when block rule matches."""

        @protect(config)
        async def delete_user(user_id: int) -> str:
            return f"Deleted user {user_id}"

        with pytest.raises(SentinelBlockedError) as exc_info:
            await delete_user(123)

        assert exc_info.value.action == "delete_user"
        assert "blocked" in exc_info.value.reason.lower()
        assert exc_info.value.awaiting_approval is False

    async def test_requires_approval_and_approves(self, config: SentinelConfig) -> None:
        """Test that action requires approval and proceeds when approved."""

        @protect(config)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount} to {destination}"

        approval_result = ApprovalResult(
            status=ApprovalStatus.APPROVED,
            action_id="test-123",
            approved_by="admin",
        )

        with patch.object(
            TerminalApprovalInterface,
            "request_approval",
            return_value=approval_result,
        ):
            result = await transfer_funds(amount=150.0, destination="user@example.com")

        assert result == "Transferred $150.0 to user@example.com"

    async def test_requires_approval_and_denies(self, config: SentinelConfig) -> None:
        """Test that action is blocked when approval is denied."""

        @protect(config)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount} to {destination}"

        approval_result = ApprovalResult(
            status=ApprovalStatus.DENIED,
            action_id="test-123",
            approved_by="admin",
            reason="Amount too high",
        )

        with patch.object(
            TerminalApprovalInterface,
            "request_approval",
            return_value=approval_result,
        ):
            with pytest.raises(SentinelBlockedError) as exc_info:
                await transfer_funds(amount=150.0, destination="user@example.com")

        assert exc_info.value.action == "transfer_funds"
        assert exc_info.value.awaiting_approval is False

    async def test_requires_approval_timeout_in_secure_mode(
        self, config: SentinelConfig
    ) -> None:
        """Test that timeout blocks action in secure mode."""

        @protect(config)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount} to {destination}"

        approval_result = ApprovalResult(
            status=ApprovalStatus.TIMEOUT,
            action_id="test-123",
        )

        with patch.object(
            TerminalApprovalInterface,
            "request_approval",
            return_value=approval_result,
        ):
            with pytest.raises(SentinelTimeoutError):
                await transfer_funds(amount=150.0, destination="user@example.com")

    async def test_requires_approval_timeout_in_safe_mode(self) -> None:
        """Test that timeout allows action in safe mode."""
        config = SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            approval_interface="terminal",
            fail_mode="safe",
        )

        @protect(config)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount} to {destination}"

        approval_result = ApprovalResult(
            status=ApprovalStatus.TIMEOUT,
            action_id="test-123",
        )

        with patch.object(
            TerminalApprovalInterface,
            "request_approval",
            return_value=approval_result,
        ):
            result = await transfer_funds(amount=150.0, destination="user@example.com")

        assert result == "Transferred $150.0 to user@example.com"

    async def test_condition_with_contains_operator(
        self, config: SentinelConfig
    ) -> None:
        """Test blocking based on contains condition."""

        @protect(config)
        async def send_email(to: str, subject: str, body: str) -> str:
            return f"Sent email to {to}"

        # Should block - email to competitor domain
        with pytest.raises(SentinelBlockedError):
            await send_email(
                to="user@competitor.com",
                subject="Hello",
                body="Test",
            )

        # Should allow - email to other domain
        result = await send_email(
            to="user@partner.com",
            subject="Hello",
            body="Test",
        )
        assert result == "Sent email to user@partner.com"


class TestProtectDecoratorSync:
    """Tests for the @protect decorator with sync functions."""

    @pytest.fixture
    def config(self) -> SentinelConfig:
        """Create a test config."""
        return SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            approval_interface="terminal",
        )

    def test_allows_sync_action_when_no_rules_match(
        self, config: SentinelConfig
    ) -> None:
        """Test that sync action is allowed when no rules match."""

        @protect(config)
        def read_data(data_id: int) -> str:
            return f"Data {data_id}"

        result = read_data(123)
        assert result == "Data 123"

    def test_blocks_sync_action_when_block_rule_matches(
        self, config: SentinelConfig
    ) -> None:
        """Test that sync action is blocked when block rule matches."""

        @protect(config)
        def delete_user(user_id: int) -> str:
            return f"Deleted user {user_id}"

        with pytest.raises(SentinelBlockedError):
            delete_user(123)

    def test_sync_function_preserves_return_value(
        self, config: SentinelConfig
    ) -> None:
        """Test that sync function return value is preserved."""

        @protect(config)
        def calculate_sum(a: int, b: int) -> int:
            return a + b

        result = calculate_sum(5, 3)
        assert result == 8

    def test_sync_function_preserves_exception(
        self, config: SentinelConfig
    ) -> None:
        """Test that exceptions from sync functions are preserved."""

        @protect(config)
        def failing_function() -> None:
            raise ValueError("Original error")

        with pytest.raises(ValueError, match="Original error"):
            failing_function()


class TestProtectDecoratorMetadata:
    """Tests for decorator metadata preservation."""

    @pytest.fixture
    def config(self) -> SentinelConfig:
        """Create a test config."""
        return SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            approval_interface="terminal",
        )

    def test_preserves_function_name(self, config: SentinelConfig) -> None:
        """Test that decorator preserves function name."""

        @protect(config)
        def my_function() -> None:
            """My docstring."""
            pass

        assert my_function.__name__ == "my_function"

    def test_preserves_function_docstring(self, config: SentinelConfig) -> None:
        """Test that decorator preserves function docstring."""

        @protect(config)
        def my_function() -> None:
            """My docstring."""
            pass

        assert my_function.__doc__ == "My docstring."

    async def test_preserves_async_function_name(
        self, config: SentinelConfig
    ) -> None:
        """Test that decorator preserves async function name."""

        @protect(config)
        async def my_async_function() -> None:
            """My async docstring."""
            pass

        assert my_async_function.__name__ == "my_async_function"


class TestSentinelBlockedError:
    """Tests for SentinelBlockedError exception."""

    def test_error_contains_reason(self) -> None:
        """Test that error contains reason."""
        error = SentinelBlockedError(
            reason="Action violates policy",
            action="delete_user",
        )
        assert error.reason == "Action violates policy"
        assert str(error) == "Action 'delete_user' blocked: Action violates policy"

    def test_error_contains_action_name(self) -> None:
        """Test that error contains action name."""
        error = SentinelBlockedError(
            reason="Blocked",
            action="transfer_funds",
        )
        assert error.action == "transfer_funds"

    def test_error_awaiting_approval_flag(self) -> None:
        """Test that error includes awaiting_approval flag."""
        error = SentinelBlockedError(
            reason="Requires approval",
            action="transfer_funds",
            awaiting_approval=True,
        )
        assert error.awaiting_approval is True

    def test_error_default_awaiting_approval_is_false(self) -> None:
        """Test that awaiting_approval defaults to False."""
        error = SentinelBlockedError(
            reason="Blocked",
            action="delete_user",
        )
        assert error.awaiting_approval is False


class TestFailModes:
    """Tests for fail-secure and fail-safe modes."""

    async def test_fail_secure_blocks_on_engine_error(self) -> None:
        """Test that fail-secure mode blocks when engine has error."""
        config = SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            approval_interface="terminal",
            fail_mode="secure",
        )

        @protect(config)
        async def some_action() -> str:
            return "Success"

        with patch(
            "sentinel.core.wrapper.SentinelWrapper._evaluate",
            side_effect=Exception("Engine error"),
        ):
            with pytest.raises(SentinelBlockedError) as exc_info:
                await some_action()

            assert "error" in exc_info.value.reason.lower()

    async def test_fail_safe_allows_on_engine_error(self) -> None:
        """Test that fail-safe mode allows when engine has error."""
        config = SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            approval_interface="terminal",
            fail_mode="safe",
        )

        @protect(config)
        async def some_action() -> str:
            return "Success"

        with patch(
            "sentinel.core.wrapper.SentinelWrapper._evaluate",
            side_effect=Exception("Engine error"),
        ):
            # Should not raise, but may log warning
            result = await some_action()
            assert result == "Success"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.fixture
    def config(self) -> SentinelConfig:
        """Create a test config."""
        return SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            approval_interface="terminal",
        )

    async def test_function_with_no_parameters(self, config: SentinelConfig) -> None:
        """Test function with no parameters."""

        @protect(config)
        async def get_status() -> str:
            return "OK"

        result = await get_status()
        assert result == "OK"

    async def test_function_with_kwargs(self, config: SentinelConfig) -> None:
        """Test function with keyword arguments."""

        @protect(config)
        async def transfer_funds(
            amount: float, destination: str, memo: str = ""
        ) -> str:
            return f"Transferred ${amount} to {destination} ({memo})"

        approval_result = ApprovalResult(
            status=ApprovalStatus.APPROVED,
            action_id="test-123",
        )

        with patch.object(
            TerminalApprovalInterface,
            "request_approval",
            return_value=approval_result,
        ):
            result = await transfer_funds(
                amount=150.0,
                destination="user@example.com",
                memo="Payment",
            )

        assert result == "Transferred $150.0 to user@example.com (Payment)"

    async def test_function_with_args_and_kwargs(
        self, config: SentinelConfig
    ) -> None:
        """Test function with both positional and keyword arguments."""

        @protect(config)
        async def read_data(data_id: int, format: str = "json") -> dict[str, Any]:
            return {"id": data_id, "format": format}

        result = await read_data(123, format="xml")
        assert result == {"id": 123, "format": "xml"}

    async def test_multiple_protected_functions(
        self, config: SentinelConfig
    ) -> None:
        """Test multiple protected functions don't interfere."""

        @protect(config)
        async def read_user(user_id: int) -> str:
            return f"User {user_id}"

        @protect(config)
        async def read_data(data_id: int) -> str:
            return f"Data {data_id}"

        result1 = await read_user(1)
        result2 = await read_data(2)

        assert result1 == "User 1"
        assert result2 == "Data 2"


class TestAgentId:
    """Tests for agent_id support."""

    def test_config_accepts_agent_id(self) -> None:
        """Test that SentinelConfig accepts agent_id."""
        config = SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            agent_id="test-agent",
        )
        assert config.agent_id == "test-agent"

    def test_config_agent_id_defaults_to_none(self) -> None:
        """Test that agent_id defaults to None."""
        config = SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
        )
        assert config.agent_id is None

    async def test_agent_id_included_in_blocked_error(self) -> None:
        """Test that agent_id is included in SentinelBlockedError."""
        config = SentinelConfig(
            rules_path=FIXTURES_DIR / "sample_rules.json",
            agent_id="my-agent",
        )

        @protect(config)
        async def delete_user(user_id: int) -> str:
            return f"Deleted {user_id}"

        with pytest.raises(SentinelBlockedError) as exc_info:
            await delete_user(123)

        assert exc_info.value.agent_id == "my-agent"
        assert "[my-agent]" in str(exc_info.value)
