"""Core module for Sentinel.

This module provides the main components for protecting functions
with governance rules.
"""

from sentinel.core.exceptions import (
    SentinelBlockedError,
    SentinelConfigError,
    SentinelError,
    SentinelTimeoutError,
    SentinelValidationError,
)
from sentinel.core.wrapper import (
    SentinelConfig,
    SentinelWrapper,
    clear_wrapper_cache,
    protect,
)

__all__ = [
    "protect",
    "SentinelConfig",
    "SentinelWrapper",
    "clear_wrapper_cache",
    "SentinelError",
    "SentinelBlockedError",
    "SentinelConfigError",
    "SentinelTimeoutError",
    "SentinelValidationError",
]
