"""Base interfaces for anomaly detection.

This module defines the core abstractions for anomaly detection:
- RiskLevel: Enum for categorizing risk severity
- AnomalyResult: Result of anomaly analysis
- AnomalyDetector: Abstract base class for detectors
- AnomalyEngine: Orchestrator that combines multiple detectors
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass


class RiskLevel(Enum):
    """Risk level categories for anomaly detection.

    Attributes:
        LOW: Score 0-3, no extra action needed
        MEDIUM: Score 4-6, log warning for review
        HIGH: Score 7-8, force approval even without rule match
        CRITICAL: Score 9-10, block automatically
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_score(cls, score: float) -> RiskLevel:
        """Determine risk level from numeric score.

        Args:
            score: Risk score from 0.0 to 10.0

        Returns:
            Corresponding RiskLevel enum value.
        """
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        else:
            return cls.LOW


@dataclass
class AnomalyResult:
    """Result of anomaly analysis.

    Attributes:
        risk_score: Numeric risk score from 0.0 to 10.0
        risk_level: Categorical risk level
        reasons: Human-readable explanations for the risk
        should_escalate: Whether to force approval even without rule
        should_block: Whether to block the action automatically
        detector_type: Which detector produced this result
        confidence: Confidence in the result (0.0 to 1.0)
        metadata: Additional detector-specific data
    """

    risk_score: float
    risk_level: RiskLevel
    reasons: list[str]
    should_escalate: bool
    should_block: bool
    detector_type: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.name,
            "reasons": self.reasons,
            "should_escalate": self.should_escalate,
            "should_block": self.should_block,
            "detector_type": self.detector_type,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }


class AnomalyDetector(ABC):
    """Abstract base class for anomaly detectors.

    Implementations should analyze actions and return risk assessments
    based on their specific detection methodology.
    """

    @abstractmethod
    async def analyze(
        self,
        function_name: str,
        parameters: dict[str, Any],
        agent_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> AnomalyResult:
        """Analyze an action and return risk assessment.

        Args:
            function_name: Name of the function being called.
            parameters: Parameters passed to the function.
            agent_id: Optional identifier for the agent.
            context: Optional additional context.

        Returns:
            AnomalyResult with risk score and analysis.
        """
        pass


class AnomalyEngine:
    """Orchestrator for multiple anomaly detectors.

    Combines results from multiple detectors (statistical, LLM, etc.)
    and applies escalation/blocking thresholds.

    Attributes:
        detectors: List of active detectors.
        escalation_threshold: Score at which to force approval.
        block_threshold: Score at which to block automatically.
    """

    def __init__(
        self,
        statistical_enabled: bool = True,
        llm_enabled: bool = False,
        llm_config: dict[str, Any] | None = None,
        escalation_threshold: float = 7.0,
        block_threshold: float = 9.0,
        log_dir: str | None = None,
    ):
        """Initialize the anomaly engine.

        Args:
            statistical_enabled: Whether to use statistical detection.
            llm_enabled: Whether to use LLM-based detection.
            llm_config: Configuration for LLM detector (provider, model, etc.)
            escalation_threshold: Score at which to force approval (default: 7.0)
            block_threshold: Score at which to block (default: 9.0)
            log_dir: Directory for audit logs (for statistical detector).
        """
        self.detectors: list[AnomalyDetector] = []
        self.escalation_threshold = escalation_threshold
        self.block_threshold = block_threshold

        if statistical_enabled:
            from sentinel.anomaly.statistical import StatisticalDetector
            from pathlib import Path

            log_path = Path(log_dir) if log_dir else Path("./sentinel_logs")
            self.detectors.append(StatisticalDetector(log_dir=log_path))

        if llm_enabled:
            from sentinel.anomaly.llm_auditor import LLMAuditorDetector

            config = llm_config or {}
            self.detectors.append(LLMAuditorDetector(**config))

    async def analyze(
        self,
        function_name: str,
        parameters: dict[str, Any],
        agent_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> AnomalyResult:
        """Run all detectors and combine results.

        Args:
            function_name: Name of the function being called.
            parameters: Parameters passed to the function.
            agent_id: Optional identifier for the agent.
            context: Optional additional context.

        Returns:
            Combined AnomalyResult with highest risk score.
        """
        if not self.detectors:
            return AnomalyResult(
                risk_score=0.0,
                risk_level=RiskLevel.LOW,
                reasons=["No detectors enabled"],
                should_escalate=False,
                should_block=False,
                detector_type="none",
                confidence=0.0,
            )

        results: list[AnomalyResult] = []

        for detector in self.detectors:
            try:
                result = await detector.analyze(
                    function_name=function_name,
                    parameters=parameters,
                    agent_id=agent_id,
                    context=context,
                )
                results.append(result)
            except Exception as e:
                # Log error but continue with other detectors
                results.append(AnomalyResult(
                    risk_score=0.0,
                    risk_level=RiskLevel.LOW,
                    reasons=[f"Detector error: {str(e)}"],
                    should_escalate=False,
                    should_block=False,
                    detector_type=detector.__class__.__name__,
                    confidence=0.0,
                ))

        # Use the result with highest risk score
        max_result = max(results, key=lambda r: r.risk_score)

        # Combine reasons from all detectors that flagged issues
        all_reasons = []
        for result in results:
            if result.risk_score > 0 and result.reasons != ["No anomalies detected"]:
                all_reasons.extend(result.reasons)

        # Apply global thresholds
        should_escalate = max_result.risk_score >= self.escalation_threshold
        should_block = max_result.risk_score >= self.block_threshold

        return AnomalyResult(
            risk_score=max_result.risk_score,
            risk_level=max_result.risk_level,
            reasons=all_reasons if all_reasons else max_result.reasons,
            should_escalate=should_escalate,
            should_block=should_block,
            detector_type=max_result.detector_type,
            confidence=max_result.confidence,
            metadata={
                "all_results": [r.to_dict() for r in results],
                "escalation_threshold": self.escalation_threshold,
                "block_threshold": self.block_threshold,
            },
        )
