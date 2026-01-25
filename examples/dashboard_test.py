"""Test script for Dashboard approval flow.

Usage:
1. Start the dashboard: python -m sentinel.dashboard
2. Run this test: python examples/dashboard_test.py
3. Approve/deny requests in the dashboard UI at http://localhost:8501

The dashboard runs two servers:
- FastAPI on port 8000 (API for approval requests)
- Streamlit on port 8501 (Dashboard UI)

Environment Variables:
- SENTINEL_WEBHOOK_URL: URL to POST approval requests (default: http://localhost:8000/approval)
- SENTINEL_STATUS_URL: URL template for status polling (default: http://localhost:8000/approval/{action_id}/status)
- SENTINEL_WEBHOOK_TOKEN: Authentication token (default: local-test-token)
- SENTINEL_WEBHOOK_TIMEOUT: Timeout in seconds (default: 120)
- SENTINEL_POLL_INTERVAL: Poll interval in seconds (default: 2)
"""

import asyncio
import os
from pathlib import Path

from sentinel import SentinelConfig, SentinelBlockedError, protect
from sentinel.approval.webhook import WebhookApprovalInterface


# Default URLs for local development with Sentinel Dashboard
DEFAULT_WEBHOOK_URL = "http://localhost:8000/approval"
DEFAULT_STATUS_URL = "http://localhost:8000/approval/{action_id}/status"

# Connect to the local Dashboard API (FastAPI on port 8000)
# NOTE: The API runs on port 8000, NOT 8501 (which is the Streamlit UI)
webhook = WebhookApprovalInterface(
    webhook_url=os.environ.get("SENTINEL_WEBHOOK_URL", DEFAULT_WEBHOOK_URL),
    status_url_template=os.environ.get("SENTINEL_STATUS_URL", DEFAULT_STATUS_URL),
    token=os.environ.get("SENTINEL_WEBHOOK_TOKEN", "local-test-token"),
    timeout_seconds=int(os.environ.get("SENTINEL_WEBHOOK_TIMEOUT", "120")),
    poll_interval_seconds=int(os.environ.get("SENTINEL_POLL_INTERVAL", "2")),
)


def get_context():
    return {
        "current_balance": 5000.00,
        "daily_limit": 10000.00,
        "account_status": "active",
    }


config = SentinelConfig(
    rules_path=Path(__file__).parent.parent / "config" / "rules.json",
    approval_interface=webhook,
    agent_id="dashboard-test-agent",
    audit_log=True,
)


@protect(config, context_fn=get_context)
async def transfer_funds(amount: float, destination: str) -> str:
    return f"Transferred ${amount} to {destination}"


async def main():
    print("=" * 60)
    print("Dashboard Approval Test")
    print("=" * 60)
    print()
    print("Dashboard UI:  http://localhost:8501")
    print("Dashboard API: http://localhost:8000")
    print()
    print("Make sure the dashboard is running:")
    print("  python -m sentinel.dashboard")
    print()
    print("Steps:")
    print("1. Open http://localhost:8501 in your browser")
    print("2. Watch for the pending approval to appear")
    print("3. Click APPROVE or DENY")
    print()
    print("-" * 60)
    print()
    print("Sending transfer request for $500...")
    print("(Waiting for your approval in the dashboard)")
    print()

    try:
        result = await transfer_funds(500.0, "vendor@example.com")
        print(f"✅ SUCCESS: {result}")
    except SentinelBlockedError as e:
        print(f"❌ BLOCKED: {e.reason}")
    except Exception as e:
        print(f"⚠️ ERROR: {e}")

    print()
    print("Test complete!")


if __name__ == "__main__":
    asyncio.run(main())