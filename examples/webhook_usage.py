"""Webhook approval interface usage example.

This example demonstrates how to use Sentinel with webhook-based
approval for distributed approval workflows.

## Testing with Sentinel Dashboard (Recommended)

1. Start the dashboard: python -m sentinel.dashboard
2. Run this script with: python examples/webhook_usage.py --dashboard
3. Approve/deny requests in the dashboard UI at http://localhost:8501

## Testing with webhook.site

1. Go to https://webhook.site and copy your unique URL
2. Set environment variables:
   export SENTINEL_WEBHOOK_URL="https://webhook.site/your-unique-id"
   export SENTINEL_STATUS_URL="https://webhook.site/your-unique-id/{action_id}"
3. Run this script (without --dashboard flag)
4. Watch requests appear on webhook.site

Note: webhook.site doesn't support the polling endpoint,
so this example will timeout. For a real integration,
you need a backend that implements both endpoints.

## Environment Variables

- SENTINEL_WEBHOOK_URL: URL to POST approval requests (default: http://localhost:8000/approval)
- SENTINEL_STATUS_URL: URL template for status polling (default: http://localhost:8000/approval/{action_id}/status)
- SENTINEL_WEBHOOK_TOKEN: Authentication token for webhook requests (default: sk-sentinel-demo-token)

## Real Integration

Your backend needs to implement:

POST /approval
- Receives approval request
- Stores it for human review
- Returns 202 Accepted

GET /approval/{action_id}/status
- Returns {"status": "pending|approved|denied", ...}
- Updated when human approves/denies

"""

import argparse
import asyncio
import os
from pathlib import Path

from sentinel import SentinelConfig, SentinelBlockedError, protect
from sentinel.approval.webhook import WebhookApprovalInterface


# Default URLs for local development with Sentinel Dashboard
DEFAULT_WEBHOOK_URL = "http://localhost:8000/approval"
DEFAULT_STATUS_URL = "http://localhost:8000/approval/{action_id}/status"
DEFAULT_WEBHOOK_TOKEN = "sk-sentinel-demo-token"

# Parse arguments to choose mode
parser = argparse.ArgumentParser()
parser.add_argument("--dashboard", action="store_true", help="Use local Sentinel Dashboard (ignores env vars)")
args, _ = parser.parse_known_args()

# Get URLs from environment variables, with defaults for local development
if args.dashboard:
    # Force local dashboard URLs when --dashboard flag is used
    WEBHOOK_URL = DEFAULT_WEBHOOK_URL
    STATUS_URL = DEFAULT_STATUS_URL
else:
    # Use environment variables if set, otherwise use defaults
    WEBHOOK_URL = os.environ.get("SENTINEL_WEBHOOK_URL", DEFAULT_WEBHOOK_URL)
    STATUS_URL = os.environ.get("SENTINEL_STATUS_URL", DEFAULT_STATUS_URL)

WEBHOOK_TOKEN = os.environ.get("SENTINEL_WEBHOOK_TOKEN", DEFAULT_WEBHOOK_TOKEN)


# Create webhook approval interface
webhook_interface = WebhookApprovalInterface(
    webhook_url=WEBHOOK_URL,
    status_url_template=STATUS_URL,
    token=WEBHOOK_TOKEN,
    timeout_seconds=int(os.environ.get("SENTINEL_WEBHOOK_TIMEOUT", "10")),
    poll_interval_seconds=int(os.environ.get("SENTINEL_POLL_INTERVAL", "2")),
)

# Configure Sentinel with webhook approval
config = SentinelConfig(
    rules_path=Path(__file__).parent.parent / "config" / "rules.json",
    approval_interface=webhook_interface,
    fail_mode="secure",
    agent_id="webhook-demo-agent",
)


@protect(config)
async def transfer_funds(amount: float, destination: str) -> str:
    """Transfer funds - requires approval for amounts > $100."""
    return f"Transferred ${amount} to {destination}"


@protect(config)
async def delete_user(user_id: int) -> str:
    """Delete user - always blocked by policy."""
    return f"Deleted user {user_id}"


async def main() -> None:
    """Run the webhook demo."""
    print("=" * 60)
    print("Sentinel Webhook Approval Demo")
    print("=" * 60)
    print()

    if args.dashboard:
        print("Mode: Sentinel Dashboard (local)")
        print("  Dashboard UI: http://localhost:8501")
        print("  API endpoint: http://localhost:8000")
        print()
        print("Make sure the dashboard is running:")
        print("  python -m sentinel.dashboard")
    else:
        print("Mode: webhook.site (external)")
        print("  Note: This will timeout since webhook.site doesn't respond")

    print()
    print(f"Webhook URL: {WEBHOOK_URL}")
    print(f"Status URL: {STATUS_URL}")
    print()

    # Example 1: Action that requires approval
    print("1. Attempting large transfer ($500)...")
    print("   This will send a webhook and poll for approval.")
    print("   (Will timeout since webhook.site doesn't respond)")
    print()

    try:
        result = await transfer_funds(500.0, "user@example.com")
        print(f"   SUCCESS: {result}")
    except SentinelBlockedError as e:
        print(f"   BLOCKED: {e.reason}")
    except Exception as e:
        print(f"   ERROR: {e}")

    print()

    # Example 2: Action that's always blocked
    print("2. Attempting to delete user...")
    print("   This is blocked by policy (no webhook sent).")
    print()

    try:
        result = await delete_user(123)
        print(f"   SUCCESS: {result}")
    except SentinelBlockedError as e:
        print(f"   BLOCKED: {e.reason}")

    print()
    print("=" * 60)
    print("Demo complete!")
    print("=" * 60)

    # Clean up
    await webhook_interface.close()


if __name__ == "__main__":
    asyncio.run(main())
