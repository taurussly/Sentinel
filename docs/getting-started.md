# Getting Started with Sentinel

Get up and running with Sentinel in under 5 minutes.

## Installation

```bash
pip install sentinel-ai
```

For dashboard support:
```bash
pip install sentinel-ai[dashboard]
```

For LangChain integration:
```bash
pip install sentinel-ai langchain-core
```

## Your First Protected Function

### 1. Create a rules file

Create `rules.json`:

```json
{
  "version": "1.0",
  "default_action": "allow",
  "rules": [
    {
      "id": "financial_limit",
      "function_pattern": "transfer_*",
      "conditions": [
        {"param": "amount", "operator": "gt", "value": 100}
      ],
      "action": "require_approval",
      "message": "Transfers over $100 require human approval"
    }
  ]
}
```

### 2. Protect your function

Create `main.py`:

```python
import asyncio
from sentinel import SentinelConfig, protect

config = SentinelConfig(
    rules_path="rules.json",
    approval_interface="terminal",
)

@protect(config)
async def transfer_funds(amount: float, destination: str) -> str:
    # Your actual transfer logic here
    return f"Transferred ${amount} to {destination}"

async def main():
    # This will execute immediately (under $100)
    result = await transfer_funds(50.0, "user@example.com")
    print(result)
    
    # This will require approval (over $100)
    result = await transfer_funds(500.0, "vendor@example.com")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
```

### 3. Run it

```bash
python main.py
```

You'll see:
```
Transferred $50.0 to user@example.com

============================================================
🛡️ SENTINEL APPROVAL REQUIRED
============================================================
Function: transfer_funds
Amount: $500.0
Destination: vendor@example.com

Reason: Transfers over $100 require human approval
------------------------------------------------------------
Approve? [y/n]: 
```

Type `y` to approve, `n` to deny.

## Next Steps

- [Configure rules](configuration.md) - Learn the full rule syntax
- [Add context](approval-interfaces.md#context) - Show approvers relevant info
- [Enable audit logging](configuration.md#audit-logging) - Track all actions
- [Use the Dashboard](dashboard.md) - Visual approval interface
- [Enable anomaly detection](anomaly-detection.md) - Catch unusual patterns

## Quick Reference

```python
from sentinel import SentinelConfig, protect, SentinelBlockedError

# Full configuration
config = SentinelConfig(
    rules_path="rules.json",           # Required: path to rules
    approval_interface="terminal",      # "terminal", "webhook", or custom
    fail_mode="secure",                 # "secure" (block on error) or "safe"
    agent_id="my-agent",               # Identifier for this agent
    audit_log=True,                    # Enable audit logging
    audit_log_dir="./logs",            # Where to save logs
    anomaly_detection=True,            # Enable anomaly detection
)

# With context for better decisions
def get_context():
    return {
        "current_balance": 5000.00,
        "daily_limit_remaining": 2000.00,
    }

@protect(config, context_fn=get_context)
async def my_function():
    pass

# Handle blocked actions
try:
    await my_function()
except SentinelBlockedError as e:
    print(f"Blocked: {e.reason}")
```
