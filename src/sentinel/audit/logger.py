"""Local audit logging for Sentinel.

Logs all Sentinel events (allow, block, approval) to JSON files
for debugging and compliance preparation.

Log files are stored in JSONL format (JSON Lines), where each line
is a complete JSON object representing one event.
"""

from __future__ import annotations

import json
import logging
from datetime import date
from pathlib import Path
from typing import Any

from sentinel.audit.models import AuditEvent

logger = logging.getLogger(__name__)


class AuditLogger:
    """Audit logger that writes events to daily JSONL files.

    Events are appended to files named YYYY-MM-DD.jsonl in the
    configured log directory.

    Attributes:
        log_dir: Directory where log files are stored.
        enabled: Whether logging is enabled.
    """

    def __init__(
        self,
        log_dir: Path | str = Path("./sentinel_logs"),
        enabled: bool = True,
    ) -> None:
        """Initialize the audit logger.

        Args:
            log_dir: Directory for log files (created if needed).
            enabled: Whether logging is enabled.
        """
        self.log_dir = Path(log_dir)
        self.enabled = enabled

        if self.enabled:
            self._ensure_log_dir()

    def _ensure_log_dir(self) -> None:
        """Create log directory if it doesn't exist."""
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create audit log directory: {e}")
            self.enabled = False

    def _get_log_file(self, for_date: date | None = None) -> Path:
        """Get the log file path for a given date.

        Args:
            for_date: Date for the log file (defaults to today).

        Returns:
            Path to the log file.
        """
        log_date = for_date or date.today()
        return self.log_dir / f"{log_date.isoformat()}.jsonl"

    def log(self, event: AuditEvent) -> None:
        """Append an event to the daily log file.

        Args:
            event: The audit event to log.
        """
        if not self.enabled:
            return

        log_file = self._get_log_file()

        try:
            with open(log_file, "a", encoding="utf-8") as f:
                json_line = json.dumps(event.to_dict(), ensure_ascii=False)
                f.write(json_line + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def log_allow(
        self,
        function_name: str,
        parameters: dict[str, Any],
        agent_id: str | None = None,
        duration_ms: float = 0.0,
    ) -> None:
        """Log an allowed action (no rule match).

        Args:
            function_name: Name of the function.
            parameters: Function parameters.
            agent_id: Optional agent identifier.
            duration_ms: Processing duration in milliseconds.
        """
        event = AuditEvent.create(
            event_type="allow",
            function_name=function_name,
            parameters=parameters,
            result="executed",
            agent_id=agent_id,
            duration_ms=duration_ms,
        )
        self.log(event)

    def log_block(
        self,
        function_name: str,
        parameters: dict[str, Any],
        rule_id: str,
        reason: str,
        agent_id: str | None = None,
        duration_ms: float = 0.0,
    ) -> None:
        """Log a blocked action.

        Args:
            function_name: Name of the function.
            parameters: Function parameters.
            rule_id: ID of the blocking rule.
            reason: Reason for blocking.
            agent_id: Optional agent identifier.
            duration_ms: Processing duration in milliseconds.
        """
        event = AuditEvent.create(
            event_type="block",
            function_name=function_name,
            parameters=parameters,
            result="blocked",
            rule_id=rule_id,
            reason=reason,
            agent_id=agent_id,
            duration_ms=duration_ms,
        )
        self.log(event)

    def log_approval_requested(
        self,
        function_name: str,
        parameters: dict[str, Any],
        action_id: str,
        rule_id: str,
        context: dict[str, Any] | None = None,
        agent_id: str | None = None,
    ) -> None:
        """Log an approval request.

        Args:
            function_name: Name of the function.
            parameters: Function parameters.
            action_id: Unique action identifier.
            rule_id: ID of the rule requiring approval.
            context: Optional context for the approver.
            agent_id: Optional agent identifier.
        """
        event = AuditEvent.create(
            event_type="approval_requested",
            function_name=function_name,
            parameters=parameters,
            result="pending",
            action_id=action_id,
            rule_id=rule_id,
            context=context,
            agent_id=agent_id,
        )
        self.log(event)

    def log_approval_granted(
        self,
        function_name: str,
        parameters: dict[str, Any],
        action_id: str,
        approved_by: str | None = None,
        agent_id: str | None = None,
        duration_ms: float = 0.0,
    ) -> None:
        """Log an approved action.

        Args:
            function_name: Name of the function.
            parameters: Function parameters.
            action_id: Unique action identifier.
            approved_by: Who approved the action.
            agent_id: Optional agent identifier.
            duration_ms: Processing duration in milliseconds.
        """
        event = AuditEvent.create(
            event_type="approval_granted",
            function_name=function_name,
            parameters=parameters,
            result="executed",
            action_id=action_id,
            approved_by=approved_by,
            agent_id=agent_id,
            duration_ms=duration_ms,
        )
        self.log(event)

    def log_approval_denied(
        self,
        function_name: str,
        parameters: dict[str, Any],
        action_id: str,
        approved_by: str | None = None,
        reason: str | None = None,
        agent_id: str | None = None,
        duration_ms: float = 0.0,
    ) -> None:
        """Log a denied action.

        Args:
            function_name: Name of the function.
            parameters: Function parameters.
            action_id: Unique action identifier.
            approved_by: Who denied the action.
            reason: Reason for denial.
            agent_id: Optional agent identifier.
            duration_ms: Processing duration in milliseconds.
        """
        event = AuditEvent.create(
            event_type="approval_denied",
            function_name=function_name,
            parameters=parameters,
            result="blocked",
            action_id=action_id,
            approved_by=approved_by,
            reason=reason,
            agent_id=agent_id,
            duration_ms=duration_ms,
        )
        self.log(event)

    def log_approval_timeout(
        self,
        function_name: str,
        parameters: dict[str, Any],
        action_id: str,
        agent_id: str | None = None,
        duration_ms: float = 0.0,
    ) -> None:
        """Log a timed-out approval request.

        Args:
            function_name: Name of the function.
            parameters: Function parameters.
            action_id: Unique action identifier.
            agent_id: Optional agent identifier.
            duration_ms: Processing duration in milliseconds.
        """
        event = AuditEvent.create(
            event_type="approval_timeout",
            function_name=function_name,
            parameters=parameters,
            result="blocked",
            action_id=action_id,
            agent_id=agent_id,
            duration_ms=duration_ms,
        )
        self.log(event)

    def log_anomaly(
        self,
        function_name: str,
        parameters: dict[str, Any],
        risk_score: float,
        risk_level: str,
        reasons: list[str],
        agent_id: str | None = None,
    ) -> None:
        """Log an anomaly detection event.

        Args:
            function_name: Name of the function.
            parameters: Function parameters.
            risk_score: Anomaly risk score (0-10).
            risk_level: Risk level category.
            reasons: List of reasons for the anomaly.
            agent_id: Optional agent identifier.
        """
        event = AuditEvent.create(
            event_type="anomaly_detected",
            function_name=function_name,
            parameters=parameters,
            result="flagged",
            reason=f"Risk {risk_score:.1f} ({risk_level}): {'; '.join(reasons)}",
            agent_id=agent_id,
            metadata={
                "risk_score": risk_score,
                "risk_level": risk_level,
                "reasons": reasons,
            },
        )
        self.log(event)

    def get_events(
        self,
        for_date: date | str | None = None,
    ) -> list[AuditEvent]:
        """Read events from a log file.

        Args:
            for_date: Date to read (defaults to today).
                Can be a date object or ISO format string.

        Returns:
            List of AuditEvent objects from the log file.
        """
        if isinstance(for_date, str):
            for_date = date.fromisoformat(for_date)

        log_file = self._get_log_file(for_date)

        if not log_file.exists():
            return []

        events: list[AuditEvent] = []

        try:
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        data = json.loads(line)
                        events.append(AuditEvent.from_dict(data))
        except Exception as e:
            logger.error(f"Failed to read audit log: {e}")

        return events

    def get_events_by_agent(
        self,
        agent_id: str,
        for_date: date | str | None = None,
    ) -> list[AuditEvent]:
        """Get events for a specific agent.

        Args:
            agent_id: Agent identifier to filter by.
            for_date: Date to read (defaults to today).

        Returns:
            List of events for the specified agent.
        """
        events = self.get_events(for_date)
        return [e for e in events if e.agent_id == agent_id]

    def get_events_by_function(
        self,
        function_name: str,
        for_date: date | str | None = None,
    ) -> list[AuditEvent]:
        """Get events for a specific function.

        Args:
            function_name: Function name to filter by.
            for_date: Date to read (defaults to today).

        Returns:
            List of events for the specified function.
        """
        events = self.get_events(for_date)
        return [e for e in events if e.function_name == function_name]
