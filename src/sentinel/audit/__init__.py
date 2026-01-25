"""Audit module for Sentinel.

This module provides audit logging functionality for tracking
all Sentinel governance events.
"""

from sentinel.audit.logger import AuditLogger
from sentinel.audit.models import AuditEvent

__all__ = [
    "AuditEvent",
    "AuditLogger",
]
