"""Sentinel Command Center - Dashboard principal.

This is the main Streamlit application for the Sentinel dashboard.
It provides a visual interface for:
- Viewing pending approval requests
- Approving/denying actions
- Viewing audit log history
- Monitoring metrics
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from sentinel.audit.logger import AuditLogger
from sentinel.dashboard.state import get_state_manager

# Page configuration
st.set_page_config(
    page_title="Sentinel Command Center",
    page_icon="\U0001F6E1\uFE0F",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for better styling
st.markdown("""
<style>
    .pending-card {
        border: 2px solid #ff4b4b;
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
    }
    .stButton>button {
        width: 100%;
    }
</style>
""", unsafe_allow_html=True)


def get_audit_logger() -> AuditLogger:
    """Get or create audit logger."""
    log_dir = Path("./sentinel_logs")
    return AuditLogger(log_dir=log_dir, enabled=True)


def calculate_metrics(events: list) -> dict:
    """Calculate dashboard metrics from events."""
    metrics = {
        "value_protected": 0.0,
        "value_protected_today": 0.0,
        "actions_blocked": 0,
        "actions_blocked_today": 0,
        "actions_approved": 0,
        "actions_approved_today": 0,
        "pending_count": 0,
    }

    today = datetime.now(timezone.utc).date()

    for event in events:
        event_dict = event.to_dict() if hasattr(event, "to_dict") else event
        event_type = event_dict.get("event_type", "")
        timestamp_str = event_dict.get("timestamp", "")

        # Parse timestamp
        try:
            if "T" in timestamp_str:
                event_date = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00")).date()
            else:
                event_date = None
        except (ValueError, TypeError):
            event_date = None

        is_today = event_date == today if event_date else False

        # Calculate value protected (from blocked/denied amounts)
        if event_type in ("block", "approval_denied"):
            params = event_dict.get("parameters", {})
            amount = params.get("amount", 0)
            if isinstance(amount, (int, float)):
                metrics["value_protected"] += amount
                if is_today:
                    metrics["value_protected_today"] += amount

        # Count events
        if event_type == "block":
            metrics["actions_blocked"] += 1
            if is_today:
                metrics["actions_blocked_today"] += 1
        elif event_type == "approval_granted":
            metrics["actions_approved"] += 1
            if is_today:
                metrics["actions_approved_today"] += 1

    return metrics


def render_pending_approvals():
    """Render the pending approvals section."""
    state = get_state_manager()
    pending = state.get_all_pending()

    if not pending:
        st.success("\u2705 No pending approvals! All clear.")
        return

    for approval in pending:
        with st.container(border=True):
            col_info, col_actions = st.columns([3, 1])

            with col_info:
                st.subheader(f"\U0001F514 {approval.function_name}")
                st.caption(f"Agent: {approval.agent_id or 'unknown'} | Rule: {approval.rule_id}")

                # Parameters
                st.write("**Parameters:**")
                st.json(approval.parameters)

                # Context (if exists)
                if approval.context:
                    with st.expander("\U0001F4CB Context (for decision)"):
                        st.json(approval.context)

                st.warning(f"Reason: {approval.reason}")

            with col_actions:
                st.write("")  # Spacing

                # APPROVE button
                if st.button(
                    "\u2705 APPROVE",
                    key=f"approve_{approval.action_id}",
                    type="primary",
                    use_container_width=True,
                ):
                    state.approve(approval.action_id)
                    st.rerun()

                # DENY button
                if st.button(
                    "\u274C DENY",
                    key=f"deny_{approval.action_id}",
                    type="secondary",
                    use_container_width=True,
                ):
                    state.deny(approval.action_id)
                    st.rerun()

                # Countdown
                remaining = approval.remaining_seconds
                if remaining > 0:
                    st.caption(f"\u23F1\uFE0F Expires in {int(remaining)}s")
                else:
                    st.error("\u26A0\uFE0F EXPIRED")


def render_event_history(events: list):
    """Render the event history section."""
    if not events:
        st.info("No events recorded yet. Run some protected functions!")
        return

    # Convert to DataFrame
    df = pd.DataFrame([e.to_dict() if hasattr(e, "to_dict") else e for e in events])

    if df.empty:
        st.info("No events to display.")
        return

    # Parse timestamps
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # Timeline chart with unique key
    if "timestamp" in df.columns and "event_type" in df.columns:
        fig = px.histogram(
            df,
            x="timestamp",
            color="event_type",
            title="Events Over Time",
            color_discrete_map={
                "allow": "#28a745",
                "block": "#dc3545",
                "approval_granted": "#007bff",
                "approval_denied": "#fd7e14",
                "approval_timeout": "#6c757d",
                "approval_requested": "#17a2b8",
            },
        )
        fig.update_layout(bargap=0.1)
        st.plotly_chart(fig, use_container_width=True, key="events_chart")

    # Event table with unique key
    display_cols = ["timestamp", "event_type", "agent_id", "function_name", "result"]
    available_cols = [c for c in display_cols if c in df.columns]

    if available_cols:
        st.dataframe(
            df[available_cols].sort_values("timestamp", ascending=False),
            use_container_width=True,
            hide_index=True,
            key="events_table",
        )


def main():
    """Main dashboard function."""
    st.title("\U0001F6E1\uFE0F Sentinel Command Center")

    # Sidebar
    with st.sidebar:
        st.header("Settings")

        # Auto-refresh toggle
        auto_refresh = st.toggle("Auto-refresh", value=True)
        refresh_interval = st.slider("Refresh interval (s)", 2, 30, 5)

        st.divider()

        # Filters
        st.header("Filters")
        date_range = st.date_input(
            "Date Range",
            value=(datetime.now() - timedelta(days=7), datetime.now()),
        )
        agent_filter = st.text_input("Agent ID", placeholder="All agents")
        event_type_filter = st.multiselect(
            "Event Type",
            ["allow", "block", "approval_granted", "approval_denied", "approval_timeout"],
            default=[],
        )

        st.divider()

        # State file info
        state = get_state_manager()
        counts = state.count_by_status()
        st.caption(f"State file: {state.state_file}")
        st.caption(f"Pending: {counts['pending']} | Approved: {counts['approved']} | Denied: {counts['denied']}")

    # Load data
    audit_logger = get_audit_logger()
    events = audit_logger.get_events()
    metrics = calculate_metrics(events)
    state = get_state_manager()
    metrics["pending_count"] = len(state.get_all_pending())

    # Metrics row
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(
            "\U0001F4B0 Value Protected",
            f"${metrics['value_protected']:,.2f}",
            delta=f"+${metrics['value_protected_today']:,.2f} today" if metrics['value_protected_today'] > 0 else None,
        )

    with col2:
        st.metric(
            "\U0001F6D1 Actions Blocked",
            str(metrics["actions_blocked"]),
            delta=f"+{metrics['actions_blocked_today']} today" if metrics['actions_blocked_today'] > 0 else None,
        )

    with col3:
        st.metric(
            "\u2705 Actions Approved",
            str(metrics["actions_approved"]),
            delta=f"+{metrics['actions_approved_today']} today" if metrics['actions_approved_today'] > 0 else None,
        )

    with col4:
        st.metric(
            "\u23F3 Pending Approval",
            str(metrics["pending_count"]),
            delta_color="inverse" if metrics["pending_count"] > 0 else "off",
        )

    # Pending Approvals Section
    st.header("\U0001F6A8 Pending Approvals", divider="red")
    render_pending_approvals()

    # Event History Section
    st.header("\U0001F4CA Event History", divider="blue")

    # Apply filters
    filtered_events = events

    if agent_filter:
        filtered_events = [
            e for e in filtered_events
            if (e.to_dict() if hasattr(e, "to_dict") else e).get("agent_id") == agent_filter
        ]

    if event_type_filter:
        filtered_events = [
            e for e in filtered_events
            if (e.to_dict() if hasattr(e, "to_dict") else e).get("event_type") in event_type_filter
        ]

    render_event_history(filtered_events)

    # Auto-refresh
    if auto_refresh:
        import time
        # Use a short sleep to allow UI to render, then rerun
        time.sleep(refresh_interval)
        st.rerun()


if __name__ == "__main__":
    main()
