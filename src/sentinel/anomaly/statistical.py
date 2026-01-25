"""Statistical anomaly detection using Z-Score and pattern analysis.

This detector analyzes historical patterns from audit logs to identify
anomalous behavior without any external API calls.

Detection methods:
1. Z-Score analysis for numeric parameters (amount, quantity, etc.)
2. Call frequency analysis (calls per hour vs. historical average)
3. Time pattern analysis (unusual hours for this agent)
4. New parameter detection (values never seen before)
"""

from __future__ import annotations

import json
import logging
import statistics
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sentinel.anomaly.detector import AnomalyDetector, AnomalyResult, RiskLevel

logger = logging.getLogger(__name__)


class StatisticalDetector(AnomalyDetector):
    """Detects anomalies using statistical analysis of historical data.

    This detector is the default (free) anomaly detection method.
    It analyzes audit logs to build behavioral baselines and flags
    deviations from normal patterns.

    Attributes:
        log_dir: Directory containing audit logs.
        lookback_days: Number of days of history to analyze.
        min_samples: Minimum samples required for statistical analysis.
    """

    def __init__(
        self,
        log_dir: Path | str = Path("./sentinel_logs"),
        lookback_days: int = 30,
        min_samples: int = 5,
        cache_ttl_seconds: int = 300,
    ):
        """Initialize the statistical detector.

        Args:
            log_dir: Directory containing audit logs.
            lookback_days: Days of history to consider.
            min_samples: Minimum samples needed for statistics.
            cache_ttl_seconds: How long to cache history (default 5 min).
        """
        self.log_dir = Path(log_dir)
        self.lookback_days = lookback_days
        self.min_samples = min_samples
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, Any] = {}
        self._cache_timestamp: datetime | None = None

    async def analyze(
        self,
        function_name: str,
        parameters: dict[str, Any],
        agent_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> AnomalyResult:
        """Analyze action against historical patterns.

        Args:
            function_name: Name of the function being called.
            parameters: Parameters passed to the function.
            agent_id: Optional identifier for the agent.
            context: Optional additional context.

        Returns:
            AnomalyResult with risk assessment.
        """
        reasons: list[str] = []
        risk_scores: list[float] = []
        metadata: dict[str, Any] = {}

        # Load historical data
        history = self._load_history(agent_id, function_name)
        metadata["history_count"] = len(history)

        if len(history) < self.min_samples:
            return AnomalyResult(
                risk_score=0.0,
                risk_level=RiskLevel.LOW,
                reasons=[
                    f"Insufficient history for anomaly detection "
                    f"({len(history)} samples, need {self.min_samples})"
                ],
                should_escalate=False,
                should_block=False,
                detector_type="statistical",
                confidence=0.0,
                metadata=metadata,
            )

        # 1. Analyze numeric parameters using Z-Score
        numeric_analysis = self._analyze_numeric_params(parameters, history)
        if numeric_analysis["scores"]:
            risk_scores.extend(numeric_analysis["scores"])
            reasons.extend(numeric_analysis["reasons"])
            metadata["numeric_analysis"] = numeric_analysis["details"]

        # 2. Analyze call frequency
        frequency_result = self._analyze_frequency(agent_id, function_name, history)
        if frequency_result["score"] > 0:
            risk_scores.append(frequency_result["score"])
            reasons.append(frequency_result["reason"])
            metadata["frequency_analysis"] = frequency_result["details"]

        # 3. Analyze time pattern
        time_result = self._analyze_time_pattern(agent_id, function_name, history)
        if time_result["score"] > 0:
            risk_scores.append(time_result["score"])
            reasons.append(time_result["reason"])
            metadata["time_analysis"] = time_result["details"]

        # 4. Check for new parameter values
        new_params_result = self._check_new_parameters(parameters, history)
        if new_params_result["score"] > 0:
            risk_scores.append(new_params_result["score"])
            reasons.append(new_params_result["reason"])
            metadata["new_params"] = new_params_result["new_values"]

        # Calculate final score
        if risk_scores:
            final_score = max(risk_scores)
            confidence = min(1.0, len(history) / 100)
        else:
            final_score = 0.0
            confidence = min(1.0, len(history) / 100)

        risk_level = RiskLevel.from_score(final_score)

        return AnomalyResult(
            risk_score=final_score,
            risk_level=risk_level,
            reasons=reasons if reasons else ["No anomalies detected"],
            should_escalate=final_score >= 7.0,
            should_block=final_score >= 9.0,
            detector_type="statistical",
            confidence=confidence,
            metadata=metadata,
        )

    def _load_history(
        self,
        agent_id: str | None,
        function_name: str,
    ) -> list[dict[str, Any]]:
        """Load relevant historical events from audit logs.

        Args:
            agent_id: Filter by agent ID (optional).
            function_name: Filter by function name.

        Returns:
            List of historical event dictionaries.
        """
        now = datetime.now(timezone.utc)

        # NOTE: Caching is DISABLED for now because it caused issues where
        # newly logged events weren't seen during rapid testing.
        # The cache would return stale results from before new events were logged.
        # TODO: Implement smarter caching that checks file modification times.

        history: list[dict[str, Any]] = []
        cutoff = now - timedelta(days=self.lookback_days)

        if not self.log_dir.exists():
            logger.debug(f"Log directory does not exist: {self.log_dir}")
            return history

        # Read all log files (AuditLogger creates YYYY-MM-DD.jsonl files)
        files_found = list(self.log_dir.glob("*.jsonl"))
        logger.debug(f"Found {len(files_found)} log files in {self.log_dir}")

        for log_file in files_found:
            try:
                with open(log_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)

                            # Parse timestamp
                            ts_str = event.get("timestamp")
                            if ts_str:
                                try:
                                    event_time = datetime.fromisoformat(
                                        ts_str.replace("Z", "+00:00")
                                    )
                                except ValueError:
                                    continue
                            else:
                                continue

                            # Filter by time
                            if event_time < cutoff:
                                continue

                            # Filter by function name
                            if event.get("function_name") != function_name:
                                continue

                            # Filter by agent ID if specified
                            if agent_id and event.get("agent_id") != agent_id:
                                continue

                            history.append(event)
                        except json.JSONDecodeError:
                            continue
            except Exception as e:
                logger.warning(f"Error reading log file {log_file}: {e}")
                continue

        # Sort by timestamp (oldest first)
        history.sort(key=lambda e: e.get("timestamp", ""))

        logger.debug(
            f"Loaded {len(history)} historical events for "
            f"function={function_name}, agent={agent_id}"
        )

        return history

    def _calculate_z_score(self, value: float, historical: list[float]) -> float:
        """Calculate Z-Score of a value against historical data.

        Args:
            value: Current value to analyze.
            historical: List of historical values.

        Returns:
            Z-Score (standard deviations from mean).
        """
        if len(historical) < 2:
            return 0.0

        mean = statistics.mean(historical)
        stdev = statistics.stdev(historical)

        if stdev == 0:
            return 0.0 if value == mean else 10.0

        return (value - mean) / stdev

    def _analyze_numeric_params(
        self,
        parameters: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze numeric parameters using Z-Score.

        Args:
            parameters: Current parameters.
            history: Historical events.

        Returns:
            Dict with scores, reasons, and details.
        """
        result: dict[str, Any] = {
            "scores": [],
            "reasons": [],
            "details": {},
        }

        # Find numeric parameters
        numeric_params = {
            k: v for k, v in parameters.items()
            if isinstance(v, (int, float)) and not isinstance(v, bool)
        }

        logger.debug(f"Analyzing numeric params: {numeric_params}")

        for param_name, param_value in numeric_params.items():
            # Get historical values for this parameter
            historical_values = []
            for event in history:
                event_params = event.get("parameters", {})
                if param_name in event_params:
                    hist_val = event_params[param_name]
                    if isinstance(hist_val, (int, float)) and not isinstance(hist_val, bool):
                        historical_values.append(float(hist_val))

            logger.debug(
                f"Param '{param_name}': current={param_value}, "
                f"historical_count={len(historical_values)}, "
                f"historical_values={historical_values[:10]}{'...' if len(historical_values) > 10 else ''}"
            )

            if len(historical_values) < self.min_samples:
                logger.debug(
                    f"Skipping '{param_name}': not enough samples "
                    f"({len(historical_values)} < {self.min_samples})"
                )
                continue

            z_score = self._calculate_z_score(float(param_value), historical_values)
            mean_val = statistics.mean(historical_values)
            stdev_val = statistics.stdev(historical_values) if len(historical_values) > 1 else 0

            logger.debug(
                f"Z-Score calculation for '{param_name}': "
                f"value={param_value}, mean={mean_val:.2f}, stdev={stdev_val:.2f}, "
                f"z_score={z_score:.2f}"
            )

            result["details"][param_name] = {
                "value": param_value,
                "z_score": z_score,
                "mean": mean_val,
                "stdev": stdev_val,
                "samples": len(historical_values),
            }

            # Score based on Z-Score
            abs_z = abs(z_score)
            if abs_z > 3:
                risk = min(10.0, abs_z * 2)
                result["scores"].append(risk)
                result["reasons"].append(
                    f"Parameter '{param_name}' value {param_value} is {abs_z:.1f} "
                    f"standard deviations from mean ({mean_val:.2f})"
                )
                logger.info(
                    f"ANOMALY DETECTED: '{param_name}'={param_value} "
                    f"(z-score={z_score:.1f}, mean={mean_val:.2f}, risk={risk:.1f})"
                )
            elif abs_z > 2:
                result["scores"].append(5.0)
                result["reasons"].append(
                    f"Parameter '{param_name}' value {param_value} is unusual "
                    f"(z-score: {z_score:.2f}, mean: {mean_val:.2f})"
                )
                logger.info(
                    f"Unusual parameter: '{param_name}'={param_value} "
                    f"(z-score={z_score:.2f}, mean={mean_val:.2f})"
                )

        return result

    def _analyze_frequency(
        self,
        agent_id: str | None,
        function_name: str,
        history: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze call frequency for anomalies.

        Args:
            agent_id: Agent identifier.
            function_name: Function name.
            history: Historical events.

        Returns:
            Dict with score, reason, and details.
        """
        result: dict[str, Any] = {
            "score": 0.0,
            "reason": "",
            "details": {},
        }

        if not history:
            return result

        now = datetime.now(timezone.utc)
        one_hour_ago = now - timedelta(hours=1)

        # Count recent calls
        recent_calls = 0
        for event in history:
            ts_str = event.get("timestamp", "")
            try:
                event_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if event_time >= one_hour_ago:
                    recent_calls += 1
            except ValueError:
                continue

        # Calculate historical average calls per hour
        if len(history) >= self.min_samples:
            # Get time span of history
            timestamps = []
            for event in history:
                ts_str = event.get("timestamp", "")
                try:
                    timestamps.append(datetime.fromisoformat(ts_str.replace("Z", "+00:00")))
                except ValueError:
                    continue

            if len(timestamps) >= 2:
                timestamps.sort()
                time_span_hours = (timestamps[-1] - timestamps[0]).total_seconds() / 3600
                if time_span_hours > 0:
                    avg_calls_per_hour = len(timestamps) / time_span_hours
                else:
                    avg_calls_per_hour = 0
            else:
                avg_calls_per_hour = 0
        else:
            avg_calls_per_hour = 0

        result["details"] = {
            "recent_calls": recent_calls,
            "avg_calls_per_hour": avg_calls_per_hour,
        }

        # Flag high frequency
        if avg_calls_per_hour > 0 and recent_calls > avg_calls_per_hour * 3:
            result["score"] = 6.0
            result["reason"] = (
                f"High call frequency: {recent_calls} calls in last hour "
                f"(avg: {avg_calls_per_hour:.1f}/hour)"
            )

        return result

    def _analyze_time_pattern(
        self,
        agent_id: str | None,
        function_name: str,
        history: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze if current time is unusual for this agent/function.

        Args:
            agent_id: Agent identifier.
            function_name: Function name.
            history: Historical events.

        Returns:
            Dict with score, reason, and details.
        """
        result: dict[str, Any] = {
            "score": 0.0,
            "reason": "",
            "details": {},
        }

        if len(history) < self.min_samples:
            return result

        # Collect hours of historical calls
        hours: list[int] = []
        for event in history:
            ts_str = event.get("timestamp", "")
            try:
                event_time = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                hours.append(event_time.hour)
            except ValueError:
                continue

        if len(hours) < self.min_samples:
            return result

        # Calculate hour statistics
        hour_counts: dict[int, int] = defaultdict(int)
        for h in hours:
            hour_counts[h] += 1

        current_hour = datetime.now(timezone.utc).hour
        current_hour_count = hour_counts.get(current_hour, 0)
        total_calls = len(hours)
        current_hour_pct = (current_hour_count / total_calls) * 100 if total_calls > 0 else 0

        result["details"] = {
            "current_hour": current_hour,
            "historical_at_this_hour": current_hour_count,
            "total_historical": total_calls,
            "hour_distribution": dict(hour_counts),
        }

        # Flag if this hour has very few historical calls
        if current_hour_count == 0 and total_calls >= 20:
            result["score"] = 4.0
            result["reason"] = (
                f"Action requested at unusual time ({current_hour}:00 UTC) - "
                f"no historical activity at this hour"
            )
        elif current_hour_pct < 1.0 and total_calls >= 50:
            result["score"] = 3.0
            result["reason"] = (
                f"Action at uncommon time ({current_hour}:00 UTC) - "
                f"only {current_hour_pct:.1f}% of historical calls"
            )

        return result

    def _check_new_parameters(
        self,
        parameters: dict[str, Any],
        history: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Check for parameter values never seen before.

        Args:
            parameters: Current parameters.
            history: Historical events.

        Returns:
            Dict with score, reason, and new values found.
        """
        result: dict[str, Any] = {
            "score": 0.0,
            "reason": "",
            "new_values": [],
        }

        # Collect historical parameter values
        historical_values: dict[str, set[str]] = defaultdict(set)
        for event in history:
            event_params = event.get("parameters", {})
            for key, value in event_params.items():
                # Only track string-like parameters (destinations, emails, etc.)
                if isinstance(value, str) and len(value) < 200:
                    historical_values[key].add(value)

        # Check current parameters for new values
        new_values = []
        for key, value in parameters.items():
            if isinstance(value, str) and len(value) < 200:
                if key in historical_values and len(historical_values[key]) >= 3:
                    if value not in historical_values[key]:
                        new_values.append(f"{key}={value[:50]}")

        if new_values:
            result["new_values"] = new_values
            result["score"] = 4.0
            result["reason"] = f"New parameter values detected: {', '.join(new_values[:3])}"
            if len(new_values) > 3:
                result["reason"] += f" (+{len(new_values) - 3} more)"

        return result

    def invalidate_cache(self) -> None:
        """Clear the history cache."""
        self._cache.clear()
        self._cache_timestamp = None
