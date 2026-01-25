"""LangChain integration example for Sentinel.

This example demonstrates how to use Sentinel with LangChain tools
to add governance and human approval to AI agent actions.

Requirements:
    pip install sentinel[langchain]
    # or: pip install langchain-core

Features demonstrated:
    - protect_tool(): Wrap a single LangChain tool
    - protect_tools(): Wrap multiple tools at once
    - create_protected_tool(): Create a new protected tool from function
    - context_fn: Provide context for human approvers
    - audit_log: Log all actions to JSONL files

Note:
    Context from context_fn is shown to human approvers only.
    It is NOT returned to the LLM agent - this is intentional for privacy.
"""

import asyncio
from datetime import datetime
from pathlib import Path

# Sentinel imports
from sentinel import SentinelConfig, SentinelBlockedError
from sentinel.integrations.langchain import (
    create_protected_tool,
    protect_tool,
    protect_tools,
)

# LangChain imports (requires langchain-core)
try:
    from langchain_core.tools import BaseTool, StructuredTool
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    print("ERROR: langchain-core not installed.")
    print("Install with: pip install sentinel[langchain]")
    exit(1)


# =============================================================================
# Example 1: Create tools using LangChain's StructuredTool
# =============================================================================

def transfer_funds(amount: float, destination: str) -> str:
    """Transfer funds to a destination account.

    Args:
        amount: Amount to transfer in USD.
        destination: Email or account ID of recipient.

    Returns:
        Confirmation message.
    """
    return f"Transferred ${amount:.2f} to {destination}"


def delete_record(record_id: int, confirm: bool = False) -> str:
    """Delete a record from the database.

    Args:
        record_id: ID of the record to delete.
        confirm: Must be True to confirm deletion.

    Returns:
        Confirmation message.
    """
    if not confirm:
        return "Deletion cancelled - confirm flag not set"
    return f"Deleted record {record_id}"


def search_database(query: str, limit: int = 10) -> str:
    """Search the database for records.

    Args:
        query: Search query string.
        limit: Maximum number of results.

    Returns:
        Search results.
    """
    return f"Found {limit} results for '{query}'"


# Create standard LangChain tools
transfer_tool = StructuredTool.from_function(
    func=transfer_funds,
    name="transfer_funds",
    description="Transfer money to a destination account",
)

delete_tool = StructuredTool.from_function(
    func=delete_record,
    name="delete_record",
    description="Delete a record from the database",
)

search_tool = StructuredTool.from_function(
    func=search_database,
    name="search_database",
    description="Search the database for records",
)


# =============================================================================
# Configure Sentinel
# =============================================================================

# Context function - provides information for human approvers
# This is called ONLY when approval is required, not on every call
# IMPORTANT: Context is NOT returned to the LLM agent
def get_context() -> dict:
    """Get context for human approvers."""
    return {
        "current_user": "demo-user@example.com",
        "session_id": "sess_12345",
        "timestamp": datetime.now().isoformat(),
        "account_balance": "$10,000.00",
        "daily_transfer_limit": "$5,000.00",
        "transfers_today": "$1,200.00",
    }


# Sentinel configuration with audit logging enabled
config = SentinelConfig(
    rules_path=Path(__file__).parent.parent / "config" / "rules.json",
    approval_interface="terminal",
    fail_mode="secure",
    agent_id="langchain-demo-agent",
    audit_log=True,  # Enable audit logging
    audit_log_dir=Path("./sentinel_logs"),  # Log directory
)


# =============================================================================
# Example 2: Protect individual tool
# =============================================================================

protected_transfer = protect_tool(
    transfer_tool,
    config,
    context_fn=get_context,  # Add context for approvers
)


# =============================================================================
# Example 3: Protect multiple tools at once
# =============================================================================

protected_tools = protect_tools(
    [delete_tool, search_tool],
    config,
    context_fn=get_context,
)

protected_delete, protected_search = protected_tools


# =============================================================================
# Example 4: Create a protected tool from scratch
# =============================================================================

def send_email(to: str, subject: str, body: str) -> str:
    """Send an email message.

    Args:
        to: Recipient email address.
        subject: Email subject line.
        body: Email body content.

    Returns:
        Confirmation message.
    """
    return f"Email sent to {to}: {subject}"


protected_email = create_protected_tool(
    send_email,
    config,
    name="send_email",
    description="Send an email to a recipient",
    context_fn=get_context,
)


# =============================================================================
# Demo functions
# =============================================================================

async def demo_allowed_action():
    """Demo: Action that is allowed (no rules match)."""
    print("\n" + "=" * 60)
    print("DEMO 1: Search database (allowed)")
    print("=" * 60)
    print("Searching database - this should be allowed...")

    try:
        result = await protected_search._arun(query="customer data", limit=5)
        print(f"SUCCESS: {result}")
    except SentinelBlockedError as e:
        print(f"BLOCKED: {e.reason}")


async def demo_requires_approval():
    """Demo: Action that requires human approval."""
    print("\n" + "=" * 60)
    print("DEMO 2: Transfer funds > $100 (requires approval)")
    print("=" * 60)
    print("Attempting transfer of $500 - requires human approval...")
    print("(Context will be shown to approver but NOT returned to LLM)")

    try:
        result = await protected_transfer._arun(
            amount=500.0,
            destination="vendor@example.com"
        )
        print(f"SUCCESS: {result}")
    except SentinelBlockedError as e:
        print(f"BLOCKED: {e.reason}")


async def demo_blocked_action():
    """Demo: Action that is blocked by policy."""
    print("\n" + "=" * 60)
    print("DEMO 3: Delete record (blocked by policy)")
    print("=" * 60)
    print("Attempting to delete record - this is blocked by policy...")

    try:
        result = await protected_delete._arun(record_id=123, confirm=True)
        print(f"SUCCESS: {result}")
    except SentinelBlockedError as e:
        print(f"BLOCKED: {e.reason}")


async def demo_custom_tool():
    """Demo: Custom protected tool."""
    print("\n" + "=" * 60)
    print("DEMO 4: Send email (custom protected tool)")
    print("=" * 60)
    print("Sending email - no specific rule, should be allowed...")

    try:
        result = await protected_email._arun(
            to="customer@example.com",
            subject="Order Confirmation",
            body="Your order has been shipped."
        )
        print(f"SUCCESS: {result}")
    except SentinelBlockedError as e:
        print(f"BLOCKED: {e.reason}")


async def demo_small_transfer():
    """Demo: Small transfer (allowed, below threshold)."""
    print("\n" + "=" * 60)
    print("DEMO 5: Small transfer $50 (allowed)")
    print("=" * 60)
    print("Attempting transfer of $50 - below threshold, should be allowed...")

    try:
        result = await protected_transfer._arun(
            amount=50.0,
            destination="friend@example.com"
        )
        print(f"SUCCESS: {result}")
    except SentinelBlockedError as e:
        print(f"BLOCKED: {e.reason}")


async def main():
    """Run all demos."""
    print("=" * 60)
    print("Sentinel + LangChain Integration Demo")
    print("=" * 60)
    print()
    print("This demo shows how Sentinel protects LangChain tools.")
    print("Audit logs will be written to: ./sentinel_logs/")
    print()
    print("Rules from config/rules.json:")
    print("  - transfer_* with amount > 100: requires approval")
    print("  - delete_*: blocked")
    print("  - other actions: allowed")

    # Run demos
    await demo_allowed_action()
    await demo_small_transfer()
    await demo_blocked_action()
    await demo_custom_tool()

    # This one is interactive - requires human approval
    print("\n" + "=" * 60)
    print("INTERACTIVE: The next action requires human approval")
    print("=" * 60)
    await demo_requires_approval()

    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)
    print()
    print("Check ./sentinel_logs/ for audit log files (JSONL format).")


if __name__ == "__main__":
    asyncio.run(main())
