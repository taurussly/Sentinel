"""Anomaly detection for Sentinel.

This module provides intelligent anomaly detection to identify unusual
agent behavior beyond simple rule matching.

Two detection layers:
1. Statistical (default, zero cost) - Z-Score analysis of historical patterns
2. LLM Auditor (optional, premium) - Semantic analysis using LLMs
"""

from __future__ import annotations

from sentinel.anomaly.detector import (
    AnomalyDetector,
    AnomalyEngine,
    AnomalyResult,
    RiskLevel,
)
from sentinel.anomaly.statistical import StatisticalDetector

__all__ = [
    "AnomalyDetector",
    "AnomalyEngine",
    "AnomalyResult",
    "RiskLevel",
    "StatisticalDetector",
]

# LLMAuditorDetector is imported separately when needed
# to avoid requiring LLM dependencies by default
