# Changelog

All notable changes to Sentinel will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-25

### Added

- **Core Engine**
  - `@protect` decorator for sync and async functions
  - JSON-based rule configuration
  - `SentinelBlockedError` with structured context
  - Fail-secure and fail-safe modes

- **Rule Engine**
  - Glob pattern matching for function names
  - Conditional rules with operators (gt, lt, eq, contains, regex, etc.)
  - Three actions: allow, block, require_approval

- **Approval Interfaces**
  - Terminal-based approval (interactive y/n)
  - Webhook approval with polling
  - Context function support for informed decisions

- **Dashboard**
  - Streamlit-based visual interface
  - Real-time pending approvals list
  - Approve/Deny buttons
  - Event history with charts
  - Metrics (Value Protected, Actions Blocked, etc.)
  - FastAPI backend on port 8000
  - Streamlit frontend on port 8501

- **Anomaly Detection**
  - Statistical detection using Z-Score analysis
  - Optional LLM-based semantic detection
  - Configurable escalation and block thresholds
  - Automatic blocking for critical anomalies (score >= 9)

- **Audit Logging**
  - JSONL format for easy parsing
  - Event types: allow, block, approval_requested, approval_granted, approval_denied, approval_timeout
  - Full parameter and context logging
  - Daily log rotation

- **LangChain Integration**
  - `protect_tool()` for single tools
  - `protect_tools()` for multiple tools
  - `create_protected_tool()` decorator
  - Context function support

### Security

- Fail-secure by default (errors block actions)
- No secrets in logs
- Audit trail for compliance

---

## [Unreleased]

### Planned

- Slack/Teams approval interface
- Cloud-hosted dashboard
- SOC2 compliance package
- Multi-tenant support
- Rate limiting
- Custom approval workflows
