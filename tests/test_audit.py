"""Tests for audit logging functionality.

Tests the AuditLogger class and its integration with the Sentinel wrapper.
"""

import json
import pytest
from datetime import date, datetime
from pathlib import Path
from unittest.mock import MagicMock

from sentinel import SentinelConfig, SentinelBlockedError, protect
from sentinel.audit.logger import AuditLogger
from sentinel.audit.models import AuditEvent
from sentinel.approval.base import (
    ApprovalInterface,
    ApprovalRequest,
    ApprovalResult,
    ApprovalStatus,
)
from sentinel.core.wrapper import clear_wrapper_cache


class TestAuditEvent:
    """Tests for AuditEvent model."""

    def test_create_event(self):
        """Test creating an audit event."""
        event = AuditEvent.create(
            event_type="allow",
            function_name="test_func",
            parameters={"key": "value"},
            result="executed",
        )

        assert event.event_type == "allow"
        assert event.function_name == "test_func"
        assert event.parameters == {"key": "value"}
        assert event.result == "executed"
        assert event.timestamp is not None

    def test_event_to_dict(self):
        """Test converting event to dictionary."""
        event = AuditEvent.create(
            event_type="block",
            function_name="delete_user",
            parameters={"user_id": 123},
            result="blocked",
            rule_id="block_delete",
            reason="Delete operations blocked",
            agent_id="test-agent",
        )

        data = event.to_dict()

        assert data["event_type"] == "block"
        assert data["function_name"] == "delete_user"
        assert data["parameters"] == {"user_id": 123}
        assert data["result"] == "blocked"
        assert data["rule_id"] == "block_delete"
        assert data["reason"] == "Delete operations blocked"
        assert data["agent_id"] == "test-agent"
        assert "timestamp" in data

    def test_event_from_dict(self):
        """Test creating event from dictionary."""
        data = {
            "timestamp": "2024-01-15T10:30:00",
            "event_type": "approval_granted",
            "function_name": "transfer_funds",
            "parameters": {"amount": 500},
            "result": "executed",
            "approved_by": "admin@example.com",
        }

        event = AuditEvent.from_dict(data)

        assert event.timestamp == "2024-01-15T10:30:00"
        assert event.event_type == "approval_granted"
        assert event.function_name == "transfer_funds"
        assert event.parameters == {"amount": 500}
        assert event.approved_by == "admin@example.com"

    def test_event_with_optional_fields(self):
        """Test event with all optional fields."""
        event = AuditEvent.create(
            event_type="approval_requested",
            function_name="transfer_funds",
            parameters={"amount": 1000},
            result="pending",
            rule_id="financial_limit",
            reason="Amount exceeds threshold",
            agent_id="agent-001",
            action_id="action-123",
            approved_by="reviewer@example.com",
            context={"balance": 5000},
            duration_ms=15.5,
        )

        assert event.rule_id == "financial_limit"
        assert event.reason == "Amount exceeds threshold"
        assert event.agent_id == "agent-001"
        assert event.action_id == "action-123"
        assert event.approved_by == "reviewer@example.com"
        assert event.context == {"balance": 5000}
        assert event.duration_ms == 15.5


class TestAuditLogger:
    """Tests for AuditLogger class."""

    @pytest.fixture
    def log_dir(self, tmp_path):
        """Create temporary log directory."""
        return tmp_path / "audit_logs"

    @pytest.fixture
    def logger(self, log_dir):
        """Create an audit logger."""
        return AuditLogger(log_dir=log_dir, enabled=True)

    def test_logger_creates_directory(self, log_dir):
        """Test that logger creates the log directory."""
        assert not log_dir.exists()

        logger = AuditLogger(log_dir=log_dir, enabled=True)

        assert log_dir.exists()
        assert log_dir.is_dir()

    def test_disabled_logger(self, log_dir):
        """Test that disabled logger doesn't write."""
        logger = AuditLogger(log_dir=log_dir, enabled=False)

        event = AuditEvent.create(
            event_type="allow",
            function_name="test",
            parameters={},
            result="executed",
        )

        logger.log(event)

        # Directory should not be created when disabled
        assert not log_dir.exists()

    def test_log_event(self, logger, log_dir):
        """Test logging an event."""
        event = AuditEvent.create(
            event_type="allow",
            function_name="read_data",
            parameters={"id": 123},
            result="executed",
        )

        logger.log(event)

        # Check log file exists
        today = date.today().isoformat()
        log_file = log_dir / f"{today}.jsonl"
        assert log_file.exists()

        # Check contents
        with open(log_file) as f:
            line = f.readline()
            data = json.loads(line)

        assert data["function_name"] == "read_data"
        assert data["event_type"] == "allow"

    def test_log_allow(self, logger, log_dir):
        """Test log_allow helper method."""
        logger.log_allow(
            function_name="search",
            parameters={"query": "test"},
            agent_id="agent-1",
            duration_ms=5.0,
        )

        events = logger.get_events()
        assert len(events) == 1
        assert events[0].event_type == "allow"
        assert events[0].function_name == "search"
        assert events[0].result == "executed"
        assert events[0].duration_ms == 5.0

    def test_log_block(self, logger, log_dir):
        """Test log_block helper method."""
        logger.log_block(
            function_name="delete_user",
            parameters={"user_id": 456},
            rule_id="block_delete",
            reason="Deletion not allowed",
            agent_id="agent-1",
        )

        events = logger.get_events()
        assert len(events) == 1
        assert events[0].event_type == "block"
        assert events[0].result == "blocked"
        assert events[0].rule_id == "block_delete"
        assert events[0].reason == "Deletion not allowed"

    def test_log_approval_requested(self, logger):
        """Test log_approval_requested helper method."""
        logger.log_approval_requested(
            function_name="transfer_funds",
            parameters={"amount": 500},
            action_id="action-123",
            rule_id="financial_limit",
            context={"balance": 1000},
            agent_id="agent-1",
        )

        events = logger.get_events()
        assert len(events) == 1
        assert events[0].event_type == "approval_requested"
        assert events[0].result == "pending"
        assert events[0].action_id == "action-123"
        assert events[0].context == {"balance": 1000}

    def test_log_approval_granted(self, logger):
        """Test log_approval_granted helper method."""
        logger.log_approval_granted(
            function_name="transfer_funds",
            parameters={"amount": 500},
            action_id="action-123",
            approved_by="admin@example.com",
            agent_id="agent-1",
            duration_ms=5000.0,
        )

        events = logger.get_events()
        assert len(events) == 1
        assert events[0].event_type == "approval_granted"
        assert events[0].result == "executed"
        assert events[0].approved_by == "admin@example.com"

    def test_log_approval_denied(self, logger):
        """Test log_approval_denied helper method."""
        logger.log_approval_denied(
            function_name="transfer_funds",
            parameters={"amount": 500},
            action_id="action-123",
            approved_by="admin@example.com",
            reason="Suspicious activity",
            agent_id="agent-1",
        )

        events = logger.get_events()
        assert len(events) == 1
        assert events[0].event_type == "approval_denied"
        assert events[0].result == "blocked"
        assert events[0].reason == "Suspicious activity"

    def test_log_approval_timeout(self, logger):
        """Test log_approval_timeout helper method."""
        logger.log_approval_timeout(
            function_name="transfer_funds",
            parameters={"amount": 500},
            action_id="action-123",
            agent_id="agent-1",
            duration_ms=10000.0,
        )

        events = logger.get_events()
        assert len(events) == 1
        assert events[0].event_type == "approval_timeout"
        assert events[0].result == "blocked"

    def test_get_events_empty(self, logger):
        """Test getting events when no logs exist."""
        events = logger.get_events()
        assert events == []

    def test_get_events_multiple(self, logger):
        """Test getting multiple events."""
        logger.log_allow("func1", {"a": 1})
        logger.log_allow("func2", {"b": 2})
        logger.log_block("func3", {"c": 3}, "rule-1", "blocked")

        events = logger.get_events()
        assert len(events) == 3
        assert events[0].function_name == "func1"
        assert events[1].function_name == "func2"
        assert events[2].function_name == "func3"

    def test_get_events_by_agent(self, logger):
        """Test filtering events by agent ID."""
        logger.log_allow("func1", {}, agent_id="agent-1")
        logger.log_allow("func2", {}, agent_id="agent-2")
        logger.log_allow("func3", {}, agent_id="agent-1")

        events = logger.get_events_by_agent("agent-1")
        assert len(events) == 2
        assert all(e.agent_id == "agent-1" for e in events)

    def test_get_events_by_function(self, logger):
        """Test filtering events by function name."""
        logger.log_allow("transfer_funds", {"amount": 50})
        logger.log_allow("read_data", {"id": 1})
        logger.log_allow("transfer_funds", {"amount": 100})

        events = logger.get_events_by_function("transfer_funds")
        assert len(events) == 2
        assert all(e.function_name == "transfer_funds" for e in events)

    def test_get_events_by_date_string(self, logger):
        """Test getting events by date string."""
        logger.log_allow("test", {})

        today = date.today().isoformat()
        events = logger.get_events(for_date=today)
        assert len(events) == 1


class MockApprovalInterface(ApprovalInterface):
    """Mock approval interface for testing."""

    def __init__(self, status=ApprovalStatus.APPROVED):
        self.status = status

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        return ApprovalResult(
            status=self.status,
            action_id=request.action_id or "test-id",
            approved_by="test-user",
        )


class TestAuditIntegration:
    """Tests for audit logging integration with wrapper."""

    @pytest.fixture
    def rules_file(self, tmp_path):
        """Create rules file."""
        rules = tmp_path / "rules.json"
        rules.write_text("""
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
                },
                {
                    "id": "block_delete",
                    "name": "Block delete",
                    "function_pattern": "delete_*",
                    "conditions": [],
                    "action": "block",
                    "priority": 5,
                    "message": "Delete blocked"
                }
            ]
        }
        """)
        return rules

    @pytest.fixture
    def audit_dir(self, tmp_path):
        """Create audit log directory."""
        return tmp_path / "audit_logs"

    @pytest.fixture
    def config_with_audit(self, rules_file, audit_dir):
        """Create config with audit logging enabled."""
        clear_wrapper_cache()
        return SentinelConfig(
            rules_path=rules_file,
            approval_interface=MockApprovalInterface(ApprovalStatus.APPROVED),
            fail_mode="secure",
            agent_id="test-agent",
            audit_log=True,
            audit_log_dir=audit_dir,
        )

    @pytest.mark.asyncio
    async def test_audit_log_allow(self, config_with_audit, audit_dir):
        """Test that allowed actions are logged."""

        @protect(config_with_audit)
        async def read_data(data_id: int) -> str:
            return f"Data {data_id}"

        result = await read_data(123)

        assert result == "Data 123"

        # Check audit log
        logger = config_with_audit.get_audit_logger()
        events = logger.get_events()

        assert len(events) == 1
        assert events[0].event_type == "allow"
        assert events[0].function_name == "read_data"
        assert events[0].parameters == {"data_id": 123}
        assert events[0].agent_id == "test-agent"

    @pytest.mark.asyncio
    async def test_audit_log_block(self, config_with_audit, audit_dir):
        """Test that blocked actions are logged."""

        @protect(config_with_audit)
        async def delete_user(user_id: int) -> str:
            return f"Deleted {user_id}"

        with pytest.raises(SentinelBlockedError):
            await delete_user(456)

        # Check audit log
        logger = config_with_audit.get_audit_logger()
        events = logger.get_events()

        assert len(events) == 1
        assert events[0].event_type == "block"
        assert events[0].function_name == "delete_user"
        assert events[0].rule_id == "block_delete"

    @pytest.mark.asyncio
    async def test_audit_log_approval_granted(self, config_with_audit, audit_dir):
        """Test that approved actions are logged."""

        @protect(config_with_audit)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount}"

        result = await transfer_funds(500.0, "user@example.com")

        assert result == "Transferred $500.0"

        # Check audit log
        logger = config_with_audit.get_audit_logger()
        events = logger.get_events()

        # Should have: approval_requested, approval_granted
        assert len(events) == 2
        assert events[0].event_type == "approval_requested"
        assert events[1].event_type == "approval_granted"

    @pytest.mark.asyncio
    async def test_audit_log_approval_denied(self, rules_file, audit_dir):
        """Test that denied actions are logged."""
        clear_wrapper_cache()
        config = SentinelConfig(
            rules_path=rules_file,
            approval_interface=MockApprovalInterface(ApprovalStatus.DENIED),
            fail_mode="secure",
            agent_id="test-agent",
            audit_log=True,
            audit_log_dir=audit_dir,
        )

        @protect(config)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount}"

        with pytest.raises(SentinelBlockedError):
            await transfer_funds(500.0, "user@example.com")

        # Check audit log
        logger = config.get_audit_logger()
        events = logger.get_events()

        assert len(events) == 2
        assert events[0].event_type == "approval_requested"
        assert events[1].event_type == "approval_denied"

    @pytest.mark.asyncio
    async def test_audit_log_approval_timeout(self, rules_file, audit_dir):
        """Test that timeout actions are logged."""
        clear_wrapper_cache()
        config = SentinelConfig(
            rules_path=rules_file,
            approval_interface=MockApprovalInterface(ApprovalStatus.TIMEOUT),
            fail_mode="secure",
            agent_id="test-agent",
            audit_log=True,
            audit_log_dir=audit_dir,
        )

        @protect(config)
        async def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount}"

        from sentinel.core.exceptions import SentinelTimeoutError

        with pytest.raises(SentinelTimeoutError):
            await transfer_funds(500.0, "user@example.com")

        # Check audit log
        logger = config.get_audit_logger()
        events = logger.get_events()

        assert len(events) == 2
        assert events[0].event_type == "approval_requested"
        assert events[1].event_type == "approval_timeout"

    def test_audit_log_sync_function(self, config_with_audit, audit_dir):
        """Test that sync functions are logged."""

        @protect(config_with_audit)
        def read_data_sync(data_id: int) -> str:
            return f"Data {data_id}"

        result = read_data_sync(789)

        assert result == "Data 789"

        logger = config_with_audit.get_audit_logger()
        events = logger.get_events()

        assert len(events) == 1
        assert events[0].event_type == "allow"
        assert events[0].function_name == "read_data_sync"

    def test_audit_disabled_by_default(self, rules_file, tmp_path):
        """Test that audit logging is disabled by default."""
        clear_wrapper_cache()
        config = SentinelConfig(
            rules_path=rules_file,
            approval_interface="terminal",
            fail_mode="secure",
        )

        assert config.audit_log is False
        assert config.get_audit_logger() is None
