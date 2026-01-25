# 🛡️ Sentinel

**Zero-trust governance for AI agents. One decorator. Full control.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-205%20passed-brightgreen.svg)]()
[![Coverage](https://img.shields.io/badge/coverage-85%25-brightgreen.svg)]()

---

## The Problem

You gave your AI agent access to real tools. Now it can:
- Transfer money
- Send emails
- Delete records
- Execute code

**What could possibly go wrong?**

Everything.

---

## The Solution

```python
from sentinel import protect, SentinelConfig

config = SentinelConfig(rules_path="rules.json")

@protect(config)
async def transfer_funds(amount: float, destination: str) -> str:
    return f"Transferred ${amount} to {destination}"
```

That's it. Three lines. Your agent now requires human approval for high-risk actions.

---

## What Happens Next

```
Agent: "I'll transfer $5,000 to vendor@example.com"

============================================================
🛡️ SENTINEL APPROVAL REQUIRED
============================================================
Agent: sales-agent
Function: transfer_funds
Amount: $5,000.00
Context:
  current_balance: $10,000.00
  daily_limit_remaining: $3,000.00

Reason: Amount exceeds $100 threshold
------------------------------------------------------------
Approve? [y/n]: _
```

**You decide. Not the AI.**

---

## Features

| Feature | Description |
|---------|-------------|
| 🎯 **Rule Engine** | JSON-configurable policies (thresholds, blocks, approvals) |
| 🔔 **Multi-channel Approval** | Terminal, Webhook, or Dashboard UI |
| 📊 **Context for Decisions** | Show balance, limits, history to approvers |
| 📝 **Audit Log** | JSONL logs for compliance (GDPR, SOC2 ready) |
| 🧠 **Anomaly Detection** | Statistical analysis blocks unusual patterns |
| 🔗 **LangChain Native** | `protect_tools()` wraps any LangChain tool |
| 🖥️ **Visual Dashboard** | Streamlit UI with approve/deny buttons |

---

## Quick Start

### Installation

```bash
pip install sentinel-ai
```

### Basic Usage

```python
from sentinel import protect, SentinelConfig

config = SentinelConfig(
    rules_path="rules.json",
    approval_interface="terminal",
    fail_mode="secure",  # Block on errors, not allow
)

@protect(config)
async def delete_user(user_id: int) -> str:
    return f"Deleted user {user_id}"
```

### Rules Configuration

```json
{
  "version": "1.0",
  "default_action": "allow",
  "rules": [
    {
      "id": "financial_limit",
      "function_pattern": "transfer_*",
      "conditions": [{"param": "amount", "operator": "gt", "value": 100}],
      "action": "require_approval",
      "message": "Transfers over $100 require approval"
    },
    {
      "id": "block_deletes",
      "function_pattern": "delete_*",
      "action": "block",
      "message": "Delete operations are disabled"
    }
  ]
}
```

---

## LangChain Integration

```python
from langchain.agents import create_openai_tools_agent
from sentinel.integrations.langchain import protect_tools

# Your existing tools
tools = [search_tool, email_tool, payment_tool]

# One line to protect them all
protected_tools = protect_tools(tools, sentinel_config)

# Use as normal
agent = create_openai_tools_agent(llm, protected_tools, prompt)
```

---

## Dashboard

Start the visual command center:

```bash
pip install sentinel-ai[dashboard]
python -m sentinel.dashboard
```

Open `http://localhost:8501`:

- See pending approvals in real-time
- Click to approve or deny
- View audit history and metrics
- Track "Value Protected" across your org

**Track your protection metrics**: The dashboard shows "Total Value Protected" - the sum of all transactions that required approval. Use this metric to demonstrate ROI to stakeholders and justify governance investments.

---

## Anomaly Detection

Sentinel doesn't just check rules. It learns patterns.

```python
config = SentinelConfig(
    rules_path="rules.json",
    anomaly_detection=True,
    anomaly_statistical=True,
)
```

```
Normal behavior:    $50, $60, $70, $80, $90
Anomalous request:  $5,000

Z-Score: 311.8 standard deviations
Risk: CRITICAL (10.0)
Action: BLOCKED AUTOMATICALLY
```

No rule needed. The math speaks for itself.

---

## Fail-Secure by Default

Most systems fail-open: if something breaks, actions are allowed.

Sentinel fails-secure: if something breaks, actions are blocked.

```python
config = SentinelConfig(
    fail_mode="secure",  # Default: block on any error
    # fail_mode="safe",  # Alternative: allow on error (not recommended)
)
```

A security product that fails open isn't a security product.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      YOUR AI AGENT                          │
│  (LangChain / CrewAI / AutoGPT / Custom)                   │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   SENTINEL LAYER                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   @protect  │→ │   Rules     │→ │  Anomaly Detection  │ │
│  │  Decorator  │  │   Engine    │  │  (Z-Score Analysis) │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Approval Interface                      │   │
│  │   Terminal  |  Webhook/API  |  Dashboard UI         │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   Audit Logger                       │   │
│  │            (JSONL - Compliance Ready)               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   EXTERNAL TOOLS                            │
│  (Payment APIs, Databases, Email Services, etc.)           │
└─────────────────────────────────────────────────────────────┘
```

---

## Why Sentinel?

| Without Sentinel | With Sentinel |
|------------------|---------------|
| Agent transfers $50,000 by mistake | Agent asks permission first |
| You find out from your bank | You approve or deny in real-time |
| Logs show "function called" | Logs show who approved, when, why |
| "The AI did it" | "John approved it at 3:42 PM" |

---

## Use Cases

- **Fintech**: Approve transactions over threshold
- **HR Tech**: Review before sending offer letters
- **DevOps**: Gate production deployments
- **Healthcare**: Verify before prescription changes
- **Legal**: Review before contract modifications
- **SaaS**: Reduce impulsive cancellations

---

## Early Adopters

Sentinel is being used to protect AI agents in:

- 🏦 Financial services automation
- 📧 Customer communication workflows
- 🔧 DevOps and infrastructure management
- 📊 Data pipeline operations

*Want to be featured here? [Open an issue](https://github.com/Saladinha/Sentinel/issues) and tell us your use case!*

---

## Roadmap

- [x] Core interception engine
- [x] JSON rule configuration
- [x] Terminal approval interface
- [x] Webhook/API approval
- [x] Streamlit Dashboard
- [x] Statistical anomaly detection
- [x] LangChain integration
- [x] Audit logging (JSONL)
- [ ] Slack/Teams approval
- [ ] LLM-based semantic analysis (optional)
- [ ] Cloud-hosted dashboard
- [ ] SOC2 compliance package

---

## Configuration

Sentinel can be configured via environment variables. Copy the example file:

```bash
cp .env.example .env
```

Then edit `.env` with your values. Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_LOG_DIR` | `./sentinel_logs` | Directory for audit logs |
| `SENTINEL_FAIL_MODE` | `secure` | `secure` (block on error) or `safe` (allow on error) |
| `SENTINEL_WEBHOOK_URL` | - | URL for webhook approval requests |
| `SENTINEL_WEBHOOK_TOKEN` | - | Auth token for webhook |
| `OPENAI_API_KEY` | - | For LLM anomaly detection (optional) |

See `.env.example` for all available options.

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Clone and install dev dependencies
git clone https://github.com/Saladinha/Sentinel.git
cd sentinel
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=sentinel --cov-report=term-missing
```

---

## License

MIT License. Use it, fork it, sell it. Just don't blame us if your AI still does something stupid.

---

## Enterprise

Need custom integration, SLA, or compliance features?

**[Open an Issue →](https://github.com/Saladinha/Sentinel/issues)**

---

<p align="center">
  <strong>Stop hoping your AI behaves. Start knowing.</strong>
</p>

<p align="center">
  <a href="#quick-start">Get Started</a> •
  <a href="https://saladinha.github.io/Sentinel">Documentation</a> •
  <a href="https://github.com/Saladinha/Sentinel/issues">Report Bug</a>
</p>
