"""Basic usage example for Sentinel.

This example demonstrates how to use Sentinel to protect functions
with governance rules, including context for approval decisions
and audit logging.
"""

import asyncio
from pathlib import Path

from sentinel import SentinelConfig, SentinelBlockedError, protect


# Simulated application state (in real app, this would come from your database)
ACCOUNT_BALANCE = 600.00
DAILY_LIMIT = 1000.00
TRANSACTIONS_TODAY = 2


def get_financial_context() -> dict:
    """Get context for financial operations.
    
    This function is called when approval is required,
    providing the human approver with relevant information
    to make an informed decision.
    
    NOTE: This context is ONLY sent to the human approver,
    it is NEVER sent back to the AI/LLM.
    """
    return {
        "current_balance": ACCOUNT_BALANCE,
        "daily_limit_remaining": DAILY_LIMIT - 200,  # Simulating some spent
        "transactions_today": TRANSACTIONS_TODAY,
        "account_status": "active",
        "risk_score": "low"
    }


# Configure Sentinel with audit logging enabled
config = SentinelConfig(
    rules_path=Path(__file__).parent.parent / "config" / "rules.json",
    approval_interface="terminal",
    fail_mode="secure",
    agent_id="demo-agent",
    audit_log=True,  # Enable audit logging
    audit_log_dir=Path(__file__).parent.parent / "sentinel_logs",
)


@protect(config, context_fn=get_financial_context)
async def transfer_funds(amount: float, destination: str) -> str:
    """Transfer funds to a destination account.

    This function is protected by Sentinel. Transfers above $100
    will require human approval WITH CONTEXT showing balance and limits.
    """
    return f"Transferred ${amount} to {destination}"


@protect(config)
async def delete_user(user_id: int) -> str:
    """Delete a user account.

    This function is protected by Sentinel. All delete operations
    are blocked by policy.
    """
    return f"Deleted user {user_id}"


@protect(config)
async def read_data(data_id: int) -> str:
    """Read data from the database.

    This function is protected by Sentinel but will be allowed
    as no rules block read operations.
    """
    return f"Data for ID {data_id}"


async def main() -> None:
    """Run the example."""
    print("=" * 60)
    print("Sentinel Basic Usage Example")
    print("=" * 60)
    print("\n[Audit logging enabled - check sentinel_logs/ after running]")

    # Example 1: Allowed action (no rules match)
    print("\n1. Reading data (allowed)...")
    try:
        result = await read_data(123)
        print(f"   Result: {result}")
    except SentinelBlockedError as e:
        print(f"   Blocked: {e.reason}")

    # Example 2: Small transfer (allowed, below threshold)
    print("\n2. Small transfer $50 (allowed)...")
    try:
        result = await transfer_funds(50.0, "user@example.com")
        print(f"   Result: {result}")
    except SentinelBlockedError as e:
        print(f"   Blocked: {e.reason}")

    # Example 3: Large transfer (requires approval)
    # This will show the CONTEXT in the approval prompt!
    print("\n3. Large transfer $150 (requires approval with CONTEXT)...")
    try:
        result = await transfer_funds(150.0, "user@example.com")
        print(f"   Result: {result}")
    except SentinelBlockedError as e:
        print(f"   Blocked: {e.reason}")

    # Example 4: Delete operation (blocked by policy)
    print("\n4. Deleting user (blocked)...")
    try:
        result = await delete_user(456)
        print(f"   Result: {result}")
    except SentinelBlockedError as e:
        print(f"   Blocked: {e.reason}")

    print("\n" + "=" * 60)
    print("Example complete!")
    print("=" * 60)
    
    # Show audit log location
    log_dir = Path(__file__).parent.parent / "sentinel_logs"
    print(f"\n📋 Audit logs saved to: {log_dir.absolute()}")
    print("   Run: type sentinel_logs\\*.jsonl  (Windows)")
    print("   Run: cat sentinel_logs/*.jsonl   (Linux/Mac)")


if __name__ == "__main__":
    asyncio.run(main())