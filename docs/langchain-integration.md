# LangChain Integration

Protect your LangChain agents with one line of code.

## Installation

```bash
pip install sentinel-ai langchain-core
```

## Quick Start

```python
from langchain.agents import create_openai_tools_agent
from sentinel import SentinelConfig
from sentinel.integrations.langchain import protect_tools

# Your existing tools
tools = [search_tool, email_tool, payment_tool]

# Sentinel config
config = SentinelConfig(
    rules_path="rules.json",
    approval_interface="terminal",
)

# One line to protect all tools
protected_tools = protect_tools(tools, config)

# Use as normal
agent = create_openai_tools_agent(llm, protected_tools, prompt)
```

That's it. Every tool invocation now goes through Sentinel.

## API Reference

### protect_tool

Protect a single LangChain tool:

```python
from sentinel.integrations.langchain import protect_tool

protected = protect_tool(my_tool, config)
```

### protect_tools

Protect multiple tools at once:

```python
from sentinel.integrations.langchain import protect_tools

protected_list = protect_tools([tool1, tool2, tool3], config)
```

### create_protected_tool

Create a protected tool from a function:

```python
from sentinel.integrations.langchain import create_protected_tool

@create_protected_tool(config, name="transfer", description="Transfer funds")
def transfer_funds(amount: float, destination: str) -> str:
    return f"Transferred ${amount} to {destination}"
```

## Adding Context

Provide context for better approval decisions:

```python
def get_context():
    return {
        "user_id": current_user.id,
        "account_balance": get_balance(),
        "daily_limit_remaining": get_remaining_limit(),
    }

protected_tools = protect_tools(tools, config, context_fn=get_context)
```

The approver sees:
```
============================================================
🛡️ SENTINEL APPROVAL REQUIRED
============================================================
Function: payment_tool
Amount: $500.00

Context:
  user_id: user_123
  account_balance: $2,500.00
  daily_limit_remaining: $1,000.00
------------------------------------------------------------
Approve? [y/n]:
```

## Example: Complete Agent

```python
from langchain_openai import ChatOpenAI
from langchain.agents import create_openai_tools_agent, AgentExecutor
from langchain.tools import tool
from langchain_core.prompts import ChatPromptTemplate

from sentinel import SentinelConfig
from sentinel.integrations.langchain import protect_tools

# Define tools
@tool
def search_database(query: str) -> str:
    """Search the company database."""
    return f"Found 5 results for '{query}'"

@tool  
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a recipient."""
    return f"Email sent to {to}"

@tool
def transfer_funds(amount: float, destination: str) -> str:
    """Transfer funds to a destination account."""
    return f"Transferred ${amount} to {destination}"

# Sentinel configuration
config = SentinelConfig(
    rules_path="rules.json",
    approval_interface="terminal",
    agent_id="sales-agent",
    audit_log=True,
)

# Protect all tools
tools = [search_database, send_email, transfer_funds]
protected_tools = protect_tools(tools, config)

# Create agent
llm = ChatOpenAI(model="gpt-4")
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a helpful sales assistant."),
    ("human", "{input}"),
    ("placeholder", "{agent_scratchpad}"),
])

agent = create_openai_tools_agent(llm, protected_tools, prompt)
executor = AgentExecutor(agent=agent, tools=protected_tools)

# Run
result = executor.invoke({"input": "Transfer $500 to vendor@example.com"})
```

## Rules for LangChain Tools

Your rules file works with tool names:

```json
{
  "rules": [
    {
      "id": "approve_transfers",
      "function_pattern": "transfer_*",
      "conditions": [{"param": "amount", "operator": "gt", "value": 100}],
      "action": "require_approval"
    },
    {
      "id": "approve_emails",
      "function_pattern": "send_email",
      "conditions": [{"param": "to", "operator": "contains", "value": "@external.com"}],
      "action": "require_approval"
    },
    {
      "id": "allow_search",
      "function_pattern": "search_*",
      "action": "allow"
    }
  ]
}
```

## With Dashboard

Use webhook approval for visual management:

```python
from sentinel.approval.webhook import WebhookApprovalInterface

webhook = WebhookApprovalInterface(
    webhook_url="http://localhost:8000/approval",
    status_url_template="http://localhost:8000/approval/{action_id}/status",
    timeout_seconds=300,
)

config = SentinelConfig(
    rules_path="rules.json",
    approval_interface=webhook,
    agent_id="langchain-agent",
)

# Start dashboard in another terminal:
# python -m sentinel.dashboard

protected_tools = protect_tools(tools, config)
```

## Error Handling

When an action is blocked, `SentinelBlockedError` is raised:

```python
from sentinel import SentinelBlockedError

try:
    result = executor.invoke({"input": "Delete all records"})
except SentinelBlockedError as e:
    print(f"Agent action blocked: {e.reason}")
    # Inform the user or take alternative action
```

## Compatibility

Tested with:
- LangChain 0.1.x, 0.2.x
- langchain-core 0.1.x, 0.2.x
- Python 3.11+

Works with any LangChain tool that follows the standard `BaseTool` interface.
