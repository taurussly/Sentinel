"""Tests for LangChain integration.

Tests the protect_tool, protect_tools, and create_protected_tool functions.
"""

import pytest
from unittest.mock import MagicMock, patch

from sentinel import SentinelConfig, SentinelBlockedError
from sentinel.approval.base import (
    ApprovalInterface,
    ApprovalRequest,
    ApprovalResult,
    ApprovalStatus,
)
from sentinel.core.wrapper import clear_wrapper_cache


# Check if langchain is available
try:
    from langchain_core.tools import BaseTool, StructuredTool

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False


# Skip all tests if langchain is not installed
pytestmark = pytest.mark.skipif(
    not LANGCHAIN_AVAILABLE,
    reason="langchain-core not installed",
)


class MockApprovalInterface(ApprovalInterface):
    """Mock approval interface for testing."""

    def __init__(self, status=ApprovalStatus.APPROVED):
        self.status = status
        self.last_request = None

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        self.last_request = request
        return ApprovalResult(
            status=self.status,
            action_id=request.action_id or "test-id",
            approved_by="test-user",
        )


@pytest.fixture
def rules_file(tmp_path):
    """Create rules file."""
    rules = tmp_path / "rules.json"
    rules.write_text("""
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
            },
            {
                "id": "block_delete",
                "name": "Block deletes",
                "function_pattern": "delete_*",
                "conditions": [],
                "action": "block",
                "priority": 5,
                "message": "Delete operations blocked"
            }
        ]
    }
    """)
    return rules


@pytest.fixture
def mock_approval():
    """Create mock approval interface."""
    return MockApprovalInterface()


@pytest.fixture
def config(rules_file, mock_approval):
    """Create test config."""
    clear_wrapper_cache()
    return SentinelConfig(
        rules_path=rules_file,
        approval_interface=mock_approval,
        fail_mode="secure",
        agent_id="test-agent",
    )


class TestProtectTool:
    """Tests for protect_tool function."""

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    def test_protect_tool_basic(self, config):
        """Test basic tool protection."""
        from sentinel.integrations.langchain import protect_tool

        def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount} to {destination}"

        tool = StructuredTool.from_function(
            func=transfer_funds,
            name="transfer_funds",
            description="Transfer money",
        )

        protected = protect_tool(tool, config)

        assert protected.name == "transfer_funds"
        assert protected.description == "Transfer money"

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    @pytest.mark.asyncio
    async def test_protect_tool_allows_action(self, config):
        """Test that allowed actions pass through."""
        from sentinel.integrations.langchain import protect_tool

        def search_database(query: str) -> str:
            return f"Results for: {query}"

        tool = StructuredTool.from_function(
            func=search_database,
            name="search_database",
            description="Search the database",
        )

        protected = protect_tool(tool, config)
        result = await protected._arun(query="test query")

        assert result == "Results for: test query"

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    @pytest.mark.asyncio
    async def test_protect_tool_blocks_action(self, config):
        """Test that blocked actions raise SentinelBlockedError."""
        from sentinel.integrations.langchain import protect_tool

        def delete_record(record_id: int) -> str:
            return f"Deleted {record_id}"

        tool = StructuredTool.from_function(
            func=delete_record,
            name="delete_record",
            description="Delete a record",
        )

        protected = protect_tool(tool, config)

        with pytest.raises(SentinelBlockedError) as exc_info:
            await protected._arun(record_id=123)

        assert "blocked" in str(exc_info.value).lower()

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    @pytest.mark.asyncio
    async def test_protect_tool_requires_approval(self, config, mock_approval):
        """Test that approval is requested when required."""
        from sentinel.integrations.langchain import protect_tool

        def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount}"

        tool = StructuredTool.from_function(
            func=transfer_funds,
            name="transfer_funds",
            description="Transfer money",
        )

        protected = protect_tool(tool, config)
        result = await protected._arun(amount=500.0, destination="user@example.com")

        assert result == "Transferred $500.0"
        assert mock_approval.last_request is not None
        assert mock_approval.last_request.function_name == "transfer_funds"

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    @pytest.mark.asyncio
    async def test_protect_tool_with_context_fn(self, config, mock_approval):
        """Test that context_fn is called for approval."""
        from sentinel.integrations.langchain import protect_tool

        def transfer_funds(amount: float, destination: str) -> str:
            return f"Transferred ${amount}"

        tool = StructuredTool.from_function(
            func=transfer_funds,
            name="transfer_funds",
            description="Transfer money",
        )

        def get_context():
            return {"balance": 10000, "user": "test@example.com"}

        protected = protect_tool(tool, config, context_fn=get_context)
        result = await protected._arun(amount=500.0, destination="user@example.com")

        assert result == "Transferred $500.0"
        assert mock_approval.last_request.context is not None
        assert mock_approval.last_request.context["balance"] == 10000

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    def test_protect_tool_sync(self, config):
        """Test synchronous tool execution."""
        from sentinel.integrations.langchain import protect_tool

        def search_database(query: str) -> str:
            return f"Results for: {query}"

        tool = StructuredTool.from_function(
            func=search_database,
            name="search_database",
            description="Search",
        )

        protected = protect_tool(tool, config)
        result = protected._run(query="test")

        assert result == "Results for: test"


class TestProtectTools:
    """Tests for protect_tools function."""

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    def test_protect_tools_multiple(self, config):
        """Test protecting multiple tools at once."""
        from sentinel.integrations.langchain import protect_tools

        def tool1(x: int) -> str:
            return f"Tool1: {x}"

        def tool2(y: str) -> str:
            return f"Tool2: {y}"

        tools = [
            StructuredTool.from_function(func=tool1, name="tool1", description="T1"),
            StructuredTool.from_function(func=tool2, name="tool2", description="T2"),
        ]

        protected = protect_tools(tools, config)

        assert len(protected) == 2
        assert protected[0].name == "tool1"
        assert protected[1].name == "tool2"

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    @pytest.mark.asyncio
    async def test_protect_tools_shared_context(self, config, mock_approval):
        """Test that context_fn is shared across all protected tools."""
        from sentinel.integrations.langchain import protect_tools

        def transfer_funds(amount: float) -> str:
            return f"Transferred ${amount}"

        context_calls = []

        def get_context():
            context_calls.append(1)
            return {"shared": True}

        tools = [
            StructuredTool.from_function(
                func=transfer_funds,
                name="transfer_funds",
                description="Transfer",
            ),
        ]

        protected = protect_tools(tools, config, context_fn=get_context)

        # Should use the shared context function
        await protected[0]._arun(amount=500.0)

        assert len(context_calls) == 1
        assert mock_approval.last_request.context["shared"] is True


class TestCreateProtectedTool:
    """Tests for create_protected_tool function."""

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    def test_create_protected_tool_basic(self, config):
        """Test creating a protected tool from function."""
        from sentinel.integrations.langchain import create_protected_tool

        def my_func(x: int, y: str) -> str:
            """My function description."""
            return f"{y}: {x}"

        protected = create_protected_tool(my_func, config)

        assert protected.name == "my_func"
        assert protected.description == "My function description."

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    def test_create_protected_tool_custom_name(self, config):
        """Test creating a tool with custom name and description."""
        from sentinel.integrations.langchain import create_protected_tool

        def my_func(x: int) -> str:
            return str(x)

        protected = create_protected_tool(
            my_func,
            config,
            name="custom_name",
            description="Custom description",
        )

        assert protected.name == "custom_name"
        assert protected.description == "Custom description"

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    @pytest.mark.asyncio
    async def test_create_protected_tool_execution(self, config):
        """Test executing a created protected tool."""
        from sentinel.integrations.langchain import create_protected_tool

        def calculate(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b

        protected = create_protected_tool(calculate, config)
        result = await protected._arun(a=5, b=3)

        assert result == 8

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    @pytest.mark.asyncio
    async def test_create_protected_tool_with_context(self, config, mock_approval):
        """Test created tool with context function."""
        from sentinel.integrations.langchain import create_protected_tool

        def transfer_funds(amount: float) -> str:
            return f"Transferred ${amount}"

        def get_context():
            return {"user_id": 123}

        protected = create_protected_tool(
            transfer_funds,
            config,
            name="transfer_funds",
            context_fn=get_context,
        )

        result = await protected._arun(amount=500.0)

        assert result == "Transferred $500.0"
        assert mock_approval.last_request.context["user_id"] == 123

    @pytest.mark.skipif(not LANGCHAIN_AVAILABLE, reason="langchain not installed")
    def test_create_protected_tool_infers_schema(self, config):
        """Test that args_schema is inferred from function signature.

        Note: On Python 3.14+, pydantic v1 doesn't work, so schema inference
        may fail gracefully (args_schema will be None). This is expected.
        """
        import sys
        from sentinel.integrations.langchain import create_protected_tool

        def typed_func(name: str, age: int, active: bool = True) -> str:
            return f"{name}, {age}, {active}"

        protected = create_protected_tool(typed_func, config)

        # Check that args_schema attribute exists
        assert hasattr(protected, "args_schema")

        # On Python 3.14+, pydantic v1 doesn't work so schema may be None
        if sys.version_info >= (3, 14):
            # Just verify it doesn't crash - schema may or may not be set
            pass
        else:
            # On older Python, schema should be inferred
            assert protected.args_schema is not None


class TestLangChainImportError:
    """Tests for import error handling."""

    def test_import_error_when_langchain_missing(self, tmp_path):
        """Test that ImportError is raised when langchain is not installed."""
        # This test only makes sense when langchain IS installed
        # We'll test the _check_langchain function with a mock
        if not LANGCHAIN_AVAILABLE:
            pytest.skip("langchain not installed")

        from sentinel.integrations import langchain as lc_module

        # Save original values
        original_available = lc_module._LANGCHAIN_AVAILABLE
        original_basetool = lc_module._BaseTool

        try:
            # Simulate langchain not being available
            lc_module._LANGCHAIN_AVAILABLE = False
            lc_module._BaseTool = None

            with pytest.raises(ImportError) as exc_info:
                lc_module._check_langchain()

            assert "langchain-core" in str(exc_info.value)
            assert "pip install sentinel[langchain]" in str(exc_info.value)
        finally:
            # Restore original values
            lc_module._LANGCHAIN_AVAILABLE = original_available
            lc_module._BaseTool = original_basetool
