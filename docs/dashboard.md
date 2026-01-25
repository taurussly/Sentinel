# Dashboard

The Sentinel Command Center provides a visual interface for managing approvals.

## Installation

```bash
pip install sentinel-ai[dashboard]
```

## Starting the Dashboard

```bash
python -m sentinel.dashboard
```

Output:
```
🛡️ Sentinel Command Center
========================================
Starting API server on port 8000...
Starting Dashboard on port 8501...

Dashboard URL: http://localhost:8501
API URL: http://localhost:8000
```

## Connecting Your Agent

Configure your agent to use the dashboard API:

```python
from sentinel import SentinelConfig
from sentinel.approval.webhook import WebhookApprovalInterface

webhook = WebhookApprovalInterface(
    webhook_url="http://localhost:8000/approval",
    status_url_template="http://localhost:8000/approval/{action_id}/status",
    timeout_seconds=300,  # 5 minutes to approve
)

config = SentinelConfig(
    rules_path="rules.json",
    approval_interface=webhook,
    agent_id="my-agent",
    audit_log=True,
)
```

## Features

### Pending Approvals

- Real-time list of actions waiting for approval
- Click **APPROVE** (green) or **DENY** (red)
- See parameters, context, and reason
- Countdown timer shows time remaining

### Metrics

Top cards show:
- **Value Protected**: Sum of blocked/pending amounts
- **Actions Blocked**: Count of denied actions
- **Actions Approved**: Count of approved actions
- **Pending Approval**: Current queue size

### Event History

- Timeline chart of all events
- Filterable by date, agent, event type
- Full audit trail with timestamps

## Architecture

```
┌──────────────────┐     webhook     ┌─────────────────────┐
│   Your Agent     │ ───────────────►│   FastAPI (8000)    │
│   + Sentinel     │                 │   - POST /approval  │
│                  │◄────────────────│   - GET /status     │
└──────────────────┘     polling     └─────────────────────┘
                                              │
                                              │ shared state
                                              │ (sentinel_state.json)
                                              ▼
                                     ┌─────────────────────┐
                                     │ Streamlit (8501)    │
                                     │   - Visual UI       │
                                     │   - APPROVE/DENY    │
                                     └─────────────────────┘
                                              │
                                              ▼
                                     ┌─────────────────────┐
                                     │      Browser        │
                                     │   (You, the human)  │
                                     └─────────────────────┘
```

## API Endpoints

The FastAPI server exposes:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/approval` | POST | Receive new approval request |
| `/approval/{id}/status` | GET | Check approval status |
| `/approval/{id}/approve` | POST | Approve an action |
| `/approval/{id}/deny` | POST | Deny an action |
| `/docs` | GET | OpenAPI documentation |

## Running in Production

### With Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install sentinel-ai[dashboard]
EXPOSE 8000 8501
CMD ["python", "-m", "sentinel.dashboard"]
```

### Behind a Reverse Proxy

```nginx
server {
    listen 80;
    server_name sentinel.yourdomain.com;

    location / {
        proxy_pass http://localhost:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location /api/ {
        proxy_pass http://localhost:8000/;
    }
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SENTINEL_API_PORT` | `8000` | FastAPI port |
| `SENTINEL_DASHBOARD_PORT` | `8501` | Streamlit port |
| `SENTINEL_STATE_FILE` | `./sentinel_state.json` | State persistence |

## Security Considerations

⚠️ **The default dashboard has no authentication.**

For production:
1. Run behind a VPN or firewall
2. Add authentication proxy (OAuth, SSO)
3. Use HTTPS

## Troubleshooting

### "Connection refused" when agent sends webhook

Make sure the dashboard is running:
```bash
python -m sentinel.dashboard
```

Check the port:
```bash
curl http://localhost:8000/docs
```

### Approvals not showing in UI

The state file may not be syncing. Check:
```bash
cat sentinel_state.json
```

Force refresh the browser (Ctrl+Shift+R).

### Approval times out before I can click

Increase the timeout:
```python
webhook = WebhookApprovalInterface(
    timeout_seconds=600,  # 10 minutes
)
```
