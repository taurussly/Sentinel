"""Sentinel: Agent Governance Layer.

Sentinel is a middleware for AI agent governance that intercepts,
analyzes, and controls actions before they cause irreversible side effects.

Example:
    >>> from sentinel import protect, SentinelConfig
    >>>
    >>> config = SentinelConfig(
    ...     rules_path="config/rules.json",
    ...     approval_interface="terminal",
    ... )
    >>>
    >>> @protect(config)
    ... async def transfer_funds(amount: float, destination: str) -> str:
    ...     return f"Transferred ${amount} to {destination}"

Anomaly Detection:
    >>> config = SentinelConfig(
    ...     rules_path="config/rules.json",
    ...     anomaly_detection=True,  # Enable anomaly detection
    ...     anomaly_statistical=True,  # Use statistical detector (Z-Score)
    ...     anomaly_llm=False,  # LLM detector (optional, premium)
    ... )
"""

from sentinel.core.exceptions import (
    SentinelBlockedError,
    SentinelConfigError,
    SentinelError,
    SentinelTimeoutError,
    SentinelValidationError,
)
from sentinel.core.wrapper import SentinelConfig, SentinelWrapper, protect

__version__ = "0.1.0"

__all__ = [
    # Main API
    "protect",
    "SentinelConfig",
    "SentinelWrapper",
    # Exceptions
    "SentinelError",
    "SentinelBlockedError",
    "SentinelConfigError",
    "SentinelTimeoutError",
    "SentinelValidationError",
    # Version
    "__version__",
]
