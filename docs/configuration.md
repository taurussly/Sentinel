# Configuration Reference

Complete reference for Sentinel configuration options.

## SentinelConfig

```python
from sentinel import SentinelConfig
from pathlib import Path

config = SentinelConfig(
    # Required
    rules_path=Path("rules.json"),
    
    # Approval
    approval_interface="terminal",  # or "webhook", or custom instance
    
    # Behavior
    fail_mode="secure",  # "secure" or "safe"
    
    # Identity
    agent_id="my-agent-001",
    
    # Audit Logging
    audit_log=True,
    audit_log_dir=Path("./sentinel_logs"),
    
    # Anomaly Detection
    anomaly_detection=True,
    anomaly_statistical=True,
    anomaly_llm=False,
    anomaly_escalation_threshold=7.0,
    anomaly_block_threshold=9.0,
)
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `rules_path` | `Path \| str` | Required | Path to rules JSON file |
| `approval_interface` | `str \| ApprovalInterface` | `"terminal"` | How to request approvals |
| `fail_mode` | `"secure" \| "safe"` | `"secure"` | Behavior when errors occur |
| `agent_id` | `str \| None` | `None` | Identifier for this agent |
| `audit_log` | `bool` | `False` | Enable audit logging |
| `audit_log_dir` | `Path` | `"./sentinel_logs"` | Directory for audit logs |
| `anomaly_detection` | `bool` | `False` | Enable anomaly detection |
| `anomaly_statistical` | `bool` | `True` | Use statistical detection |
| `anomaly_llm` | `bool` | `False` | Use LLM-based detection |
| `anomaly_escalation_threshold` | `float` | `7.0` | Risk score to force approval |
| `anomaly_block_threshold` | `float` | `9.0` | Risk score to auto-block |

---

## Rules File

### Structure

```json
{
  "version": "1.0",
  "default_action": "allow",
  "rules": [
    {
      "id": "unique_rule_id",
      "function_pattern": "transfer_*",
      "conditions": [],
      "action": "require_approval",
      "message": "Human-readable reason"
    }
  ]
}
```

### Rule Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | `string` | Yes | Unique identifier for the rule |
| `function_pattern` | `string` | Yes | Glob pattern to match function names |
| `conditions` | `array` | No | Conditions that must be met |
| `action` | `string` | Yes | `"allow"`, `"block"`, or `"require_approval"` |
| `message` | `string` | No | Reason shown to approvers |

### Function Patterns

Use glob-style patterns:

| Pattern | Matches |
|---------|---------|
| `transfer_funds` | Exact match |
| `transfer_*` | `transfer_funds`, `transfer_crypto`, etc. |
| `*_user` | `delete_user`, `create_user`, etc. |
| `*` | All functions |

### Conditions

Conditions check function parameters:

```json
{
  "conditions": [
    {"param": "amount", "operator": "gt", "value": 100},
    {"param": "destination", "operator": "contains", "value": "@external.com"}
  ]
}
```

Multiple conditions use AND logic (all must match).

#### Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equals | `{"param": "status", "operator": "eq", "value": "active"}` |
| `ne` | Not equals | `{"param": "type", "operator": "ne", "value": "internal"}` |
| `gt` | Greater than | `{"param": "amount", "operator": "gt", "value": 100}` |
| `gte` | Greater or equal | `{"param": "count", "operator": "gte", "value": 10}` |
| `lt` | Less than | `{"param": "priority", "operator": "lt", "value": 5}` |
| `lte` | Less or equal | `{"param": "retry", "operator": "lte", "value": 3}` |
| `contains` | String contains | `{"param": "email", "operator": "contains", "value": "@"}` |
| `startswith` | String starts with | `{"param": "url", "operator": "startswith", "value": "https"}` |
| `endswith` | String ends with | `{"param": "file", "operator": "endswith", "value": ".exe"}` |
| `in` | Value in list | `{"param": "country", "operator": "in", "value": ["US", "UK"]}` |
| `regex` | Regex match | `{"param": "id", "operator": "regex", "value": "^[A-Z]{3}\\d+$"}` |

### Actions

| Action | Behavior |
|--------|----------|
| `allow` | Execute immediately |
| `block` | Raise `SentinelBlockedError` |
| `require_approval` | Request human approval first |

---

## Audit Logging

When `audit_log=True`, Sentinel writes JSONL files:

```
sentinel_logs/
├── 2025-01-23.jsonl
├── 2025-01-24.jsonl
└── 2025-01-25.jsonl
```

### Event Types

| Type | Description |
|------|-------------|
| `allow` | Action executed (no approval needed) |
| `block` | Action blocked by rule |
| `approval_requested` | Waiting for human approval |
| `approval_granted` | Human approved |
| `approval_denied` | Human denied |
| `approval_timeout` | Approval timed out |
| `anomaly_detected` | Anomaly detection triggered |

### Log Format

```json
{
  "timestamp": "2025-01-23T15:30:00Z",
  "event_type": "approval_granted",
  "function_name": "transfer_funds",
  "parameters": {"amount": 500.0, "destination": "vendor@example.com"},
  "agent_id": "sales-agent",
  "rule_id": "financial_limit",
  "approved_by": "john@company.com",
  "duration_ms": 15234.5,
  "action_id": "uuid-here"
}
```

---

## Fail Mode

### Secure (Default)

If Sentinel encounters an error, the action is **blocked**.

```python
config = SentinelConfig(fail_mode="secure")
```

Use when: You'd rather miss a valid action than allow a harmful one.

### Safe

If Sentinel encounters an error, the action is **allowed**.

```python
config = SentinelConfig(fail_mode="safe")
```

Use when: You can't afford downtime and have other safeguards.

---

## Environment Variables

Sentinel respects these environment variables:

### Core Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_RULES_PATH` | - | Default rules file path |
| `SENTINEL_LOG_DIR` | `./sentinel_logs` | Default audit log directory |
| `SENTINEL_FAIL_MODE` | `secure` | Default fail mode (`secure` or `safe`) |

### Webhook Approval

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_WEBHOOK_URL` | `http://localhost:8000/approval` | URL to POST approval requests |
| `SENTINEL_STATUS_URL` | `http://localhost:8000/approval/{action_id}/status` | URL template for status polling |
| `SENTINEL_WEBHOOK_TOKEN` | - | Authentication token for webhook requests |
| `SENTINEL_WEBHOOK_TIMEOUT` | `120` | Timeout in seconds for approval |
| `SENTINEL_POLL_INTERVAL` | `2` | Polling interval in seconds |

### LLM Anomaly Detection

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | - | API key for OpenAI LLM anomaly detection |
| `ANTHROPIC_API_KEY` | - | API key for Anthropic LLM anomaly detection |

### Example: Using webhook.site for testing

```bash
export SENTINEL_WEBHOOK_URL="https://webhook.site/your-unique-id"
export SENTINEL_STATUS_URL="https://webhook.site/your-unique-id/{action_id}"
python examples/webhook_usage.py
```

---

## Example Configurations

### Fintech (Strict)

```json
{
  "version": "1.0",
  "default_action": "require_approval",
  "rules": [
    {
      "id": "allow_reads",
      "function_pattern": "get_*",
      "action": "allow"
    },
    {
      "id": "block_deletes",
      "function_pattern": "delete_*",
      "action": "block"
    },
    {
      "id": "large_transfers",
      "function_pattern": "transfer_*",
      "conditions": [{"param": "amount", "operator": "gt", "value": 10000}],
      "action": "block",
      "message": "Transfers over $10k require manual processing"
    }
  ]
}
```

### DevOps (Moderate)

```json
{
  "version": "1.0",
  "default_action": "allow",
  "rules": [
    {
      "id": "prod_deployments",
      "function_pattern": "deploy_*",
      "conditions": [{"param": "environment", "operator": "eq", "value": "production"}],
      "action": "require_approval"
    },
    {
      "id": "dangerous_commands",
      "function_pattern": "execute_*",
      "conditions": [{"param": "command", "operator": "contains", "value": "rm -rf"}],
      "action": "block"
    }
  ]
}
```
