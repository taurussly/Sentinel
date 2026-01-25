"""Core wrapper and decorator for Sentinel.

This module provides the main entry points for protecting functions
with Sentinel governance:
- SentinelConfig: Configuration for the Sentinel wrapper
- SentinelWrapper: The wrapper class that intercepts function calls
- protect: Decorator for protecting functions
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Literal, ParamSpec, TypeVar, overload

from sentinel.approval.base import (
    ApprovalInterface,
    ApprovalRequest,
    ApprovalResult,
    ApprovalStatus,
)
from sentinel.approval.terminal import TerminalApprovalInterface
from sentinel.audit.logger import AuditLogger
from sentinel.core.exceptions import (
    SentinelBlockedError,
    SentinelConfigError,
    SentinelTimeoutError,
)
from sentinel.rules.engine import RuleAction, RuleResult, RulesEngine


logger = logging.getLogger(__name__)

P = ParamSpec("P")
T = TypeVar("T")

# Cache of wrappers by config id to avoid creating multiple wrappers
_wrapper_cache: dict[int, "SentinelWrapper"] = {}


def clear_wrapper_cache() -> None:
    """Clear the wrapper cache.

    This is useful for testing or when you need to force
    recreation of wrappers (e.g., after config changes).
    """
    _wrapper_cache.clear()


@dataclass
class SentinelConfig:
    """Configuration for the Sentinel wrapper.

    Attributes:
        rules_path: Path to the JSON rules file.
        approval_interface: Approval interface instance or "terminal".
        fail_mode: Behavior on errors - "secure" blocks, "safe" allows.
        timeout_seconds: Timeout for approval requests.
        agent_id: Optional identifier for the agent using this config.
        audit_log: Whether to enable audit logging (default: False).
        audit_log_dir: Directory for audit log files (default: ./sentinel_logs).
        anomaly_detection: Whether to enable anomaly detection (default: False).
        anomaly_statistical: Use statistical anomaly detection (default: True).
        anomaly_llm: Use LLM-based anomaly detection (default: False).
        anomaly_llm_provider: LLM provider for anomaly detection ("openai" or "anthropic").
        anomaly_llm_model: LLM model for anomaly detection.
        anomaly_escalation_threshold: Risk score to force approval (default: 7.0).
        anomaly_block_threshold: Risk score to auto-block (default: 9.0).
    """

    rules_path: Path
    approval_interface: ApprovalInterface | Literal["terminal"] = "terminal"
    fail_mode: Literal["secure", "safe"] = "secure"
    timeout_seconds: float = 300
    agent_id: str | None = None
    audit_log: bool = False
    audit_log_dir: Path = field(default_factory=lambda: Path("./sentinel_logs"))

    # Anomaly detection configuration
    anomaly_detection: bool = False
    anomaly_statistical: bool = True
    anomaly_llm: bool = False
    anomaly_llm_provider: str = "openai"
    anomaly_llm_model: str = "gpt-4o-mini"
    anomaly_escalation_threshold: float = 7.0
    anomaly_block_threshold: float = 9.0

    # Cached approval interface instance
    _approval_interface_instance: ApprovalInterface | None = field(
        default=None, repr=False, compare=False
    )

    # Cached audit logger instance
    _audit_logger: AuditLogger | None = field(
        default=None, repr=False, compare=False
    )

    # Cached anomaly engine instance
    _anomaly_engine: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Validate configuration and initialize approval interface."""
        # Convert string path to Path if needed
        if isinstance(self.rules_path, str):
            self.rules_path = Path(self.rules_path)

        # Convert audit_log_dir to Path if needed
        if isinstance(self.audit_log_dir, str):
            self.audit_log_dir = Path(self.audit_log_dir)

        # Validate rules file exists
        if not self.rules_path.exists():
            raise SentinelConfigError(
                f"Rules file not found: {self.rules_path}"
            )

        # Validate fail_mode
        if self.fail_mode not in ("secure", "safe"):
            raise ValueError(
                f"Invalid fail_mode: {self.fail_mode}. Must be 'secure' or 'safe'."
            )

        # Initialize approval interface
        if isinstance(self.approval_interface, str):
            if self.approval_interface == "terminal":
                self._approval_interface_instance = TerminalApprovalInterface(
                    timeout_seconds=self.timeout_seconds
                )
            else:
                raise SentinelConfigError(
                    f"Unknown approval interface: {self.approval_interface}"
                )
        else:
            self._approval_interface_instance = self.approval_interface

        # Initialize audit logger if enabled
        if self.audit_log:
            self._audit_logger = AuditLogger(
                log_dir=self.audit_log_dir,
                enabled=True,
            )

        # Initialize anomaly engine if enabled
        if self.anomaly_detection:
            from sentinel.anomaly.detector import AnomalyEngine

            llm_config = None
            if self.anomaly_llm:
                llm_config = {
                    "provider": self.anomaly_llm_provider,
                    "model": self.anomaly_llm_model,
                }

            self._anomaly_engine = AnomalyEngine(
                statistical_enabled=self.anomaly_statistical,
                llm_enabled=self.anomaly_llm,
                llm_config=llm_config,
                escalation_threshold=self.anomaly_escalation_threshold,
                block_threshold=self.anomaly_block_threshold,
                log_dir=str(self.audit_log_dir),
            )

    def get_approval_interface(self) -> ApprovalInterface:
        """Get the configured approval interface instance.

        Returns:
            The approval interface instance.
        """
        if self._approval_interface_instance is None:
            raise SentinelConfigError("Approval interface not initialized")
        return self._approval_interface_instance

    def get_audit_logger(self) -> AuditLogger | None:
        """Get the audit logger if enabled.

        Returns:
            AuditLogger instance if audit_log is True, None otherwise.
        """
        return self._audit_logger

    def get_anomaly_engine(self) -> Any:
        """Get the anomaly engine if enabled.

        Returns:
            AnomalyEngine instance if anomaly_detection is True, None otherwise.
        """
        return self._anomaly_engine


class SentinelWrapper:
    """Wrapper that intercepts function calls and applies governance rules.

    The wrapper evaluates each function call against configured rules
    and takes appropriate action:
    - Allow: Execute the function
    - Block: Raise SentinelBlockedError
    - Require Approval: Request human approval before executing

    Attributes:
        config: The Sentinel configuration.
        rules_engine: The rules evaluation engine.
        approval_interface: The approval interface instance.
    """

    def __init__(self, config: SentinelConfig) -> None:
        """Initialize the wrapper with configuration.

        Args:
            config: The Sentinel configuration.
        """
        self.config = config
        self.rules_engine = RulesEngine.from_json(config.rules_path)
        self.approval_interface = config.get_approval_interface()
        self.audit_logger = config.get_audit_logger()
        self.anomaly_engine = config.get_anomaly_engine()

    def _evaluate(
        self, function_name: str, params: dict[str, Any]
    ) -> RuleResult:
        """Evaluate rules against a function call.

        Args:
            function_name: The name of the function being called.
            params: Dictionary of function parameter names to values.

        Returns:
            RuleResult indicating the action to take.
        """
        return self.rules_engine.evaluate(function_name, params)

    async def _handle_approval(
        self,
        function_name: str,
        params: dict[str, Any],
        result: RuleResult,
        context: dict[str, Any] | None = None,
    ) -> ApprovalResult:
        """Handle the approval process for a function call.

        Args:
            function_name: The name of the function being called.
            params: Dictionary of function parameter names to values.
            result: The rule evaluation result.
            context: Optional context from context_fn for the approver.

        Returns:
            ApprovalResult indicating the approval decision.
        """
        request = ApprovalRequest(
            function_name=function_name,
            parameters=params,
            rule_id=result.rule_id or "unknown",
            message=result.message or "Approval required",
            agent_id=self.config.agent_id,
            context=context,
        )
        return await self.approval_interface.request_approval(request)

    def _extract_params(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Extract function parameters as a dictionary.

        Args:
            func: The function being called.
            args: Positional arguments passed to the function.
            kwargs: Keyword arguments passed to the function.

        Returns:
            Dictionary mapping parameter names to values.
        """
        sig = inspect.signature(func)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)

    def _get_context(self, context_fn: Callable[[], dict[str, Any]] | None) -> dict[str, Any] | None:
        """Safely call context_fn and return context.

        Args:
            context_fn: Optional function that returns context dict.

        Returns:
            Context dict if context_fn provided and succeeds, None otherwise.
        """
        if context_fn is None:
            return None

        try:
            return context_fn()
        except Exception as e:
            logger.warning(f"Error calling context_fn: {e}")
            return None

    async def execute_async(
        self,
        func: Callable[P, T],
        *args: P.args,
        context_fn: Callable[[], dict[str, Any]] | None = None,
        **kwargs: P.kwargs,
    ) -> T:
        """Execute an async function with governance checks.

        Args:
            func: The async function to execute.
            *args: Positional arguments for the function.
            context_fn: Optional function to provide context for approval.
            **kwargs: Keyword arguments for the function.

        Returns:
            The function's return value if allowed.

        Raises:
            SentinelBlockedError: If the action is blocked.
            SentinelTimeoutError: If approval times out in secure mode.
        """
        start_time = time.perf_counter()
        function_name = func.__name__
        params = self._extract_params(func, args, kwargs)

        # Anomaly detection (if enabled)
        anomaly_result = None
        force_approval = False
        if self.anomaly_engine:
            try:
                context_for_anomaly = self._get_context(context_fn)
                anomaly_result = await self.anomaly_engine.analyze(
                    function_name=function_name,
                    parameters=params,
                    agent_id=self.config.agent_id,
                    context=context_for_anomaly,
                )

                # Always log anomaly analysis for visibility
                logger.info(
                    f"Anomaly analysis: {function_name} -> "
                    f"risk={anomaly_result.risk_score:.1f} ({anomaly_result.risk_level.name}), "
                    f"reasons={anomaly_result.reasons}"
                )

                # Log to audit when risk_score > 0
                if self.audit_logger and anomaly_result.risk_score > 0:
                    self.audit_logger.log_anomaly(
                        function_name=function_name,
                        parameters=params,
                        risk_score=anomaly_result.risk_score,
                        risk_level=anomaly_result.risk_level.name,
                        reasons=anomaly_result.reasons,
                        agent_id=self.config.agent_id,
                    )

                # Auto-block if risk is critical
                if anomaly_result.should_block:
                    duration_ms = (time.perf_counter() - start_time) * 1000
                    if self.audit_logger:
                        self.audit_logger.log_block(
                            function_name=function_name,
                            parameters=params,
                            rule_id="anomaly_detection",
                            reason=f"Anomaly detected: {', '.join(anomaly_result.reasons)}",
                            agent_id=self.config.agent_id,
                            duration_ms=duration_ms,
                        )
                    raise SentinelBlockedError(
                        reason=f"Anomaly detected (risk: {anomaly_result.risk_score:.1f}): {', '.join(anomaly_result.reasons)}",
                        action=function_name,
                        agent_id=self.config.agent_id,
                    )

                # Mark for forced approval if should_escalate
                if anomaly_result.should_escalate:
                    force_approval = True
            except SentinelBlockedError:
                raise
            except Exception as e:
                logger.warning(f"Anomaly detection error: {e}")
                # Continue with normal flow if anomaly detection fails

        try:
            result = self._evaluate(function_name, params)
        except Exception as e:
            logger.error(f"Error evaluating rules: {e}")
            if self.config.fail_mode == "secure":
                raise SentinelBlockedError(
                    reason=f"Rule evaluation error: {e}",
                    action=function_name,
                    agent_id=self.config.agent_id,
                ) from e
            else:
                logger.warning(
                    f"Fail-safe mode: allowing action despite error: {e}"
                )
                return await func(*args, **kwargs)

        # Check if anomaly detection forces approval even if rules allow
        if result.is_allowed and not force_approval:
            duration_ms = (time.perf_counter() - start_time) * 1000
            if self.audit_logger:
                self.audit_logger.log_allow(
                    function_name=function_name,
                    parameters=params,
                    agent_id=self.config.agent_id,
                    duration_ms=duration_ms,
                )
            return await func(*args, **kwargs)

        if result.is_blocked and not force_approval:
            duration_ms = (time.perf_counter() - start_time) * 1000
            if self.audit_logger:
                self.audit_logger.log_block(
                    function_name=function_name,
                    parameters=params,
                    rule_id=result.rule_id or "unknown",
                    reason=result.message or "Action blocked by policy",
                    agent_id=self.config.agent_id,
                    duration_ms=duration_ms,
                )
            raise SentinelBlockedError(
                reason=result.message or "Action blocked by policy",
                action=function_name,
                agent_id=self.config.agent_id,
            )

        if result.requires_approval or force_approval:
            # Get context only when approval is required
            context = self._get_context(context_fn)

            # Enhance message if forced by anomaly detection
            if force_approval and anomaly_result:
                enhanced_result = RuleResult(
                    action=RuleAction.REQUIRE_APPROVAL,
                    rule_id=result.rule_id or "anomaly_escalation",
                    message=f"Anomaly escalation (risk: {anomaly_result.risk_score:.1f}): {', '.join(anomaly_result.reasons)}",
                )
                approval = await self._handle_approval(function_name, params, enhanced_result, context)
            else:
                approval = await self._handle_approval(function_name, params, result, context)

            # Log approval request
            if self.audit_logger:
                self.audit_logger.log_approval_requested(
                    function_name=function_name,
                    parameters=params,
                    action_id=approval.action_id,
                    rule_id=result.rule_id or "unknown",
                    context=context,
                    agent_id=self.config.agent_id,
                )

            duration_ms = (time.perf_counter() - start_time) * 1000

            if approval.is_approved:
                if self.audit_logger:
                    self.audit_logger.log_approval_granted(
                        function_name=function_name,
                        parameters=params,
                        action_id=approval.action_id,
                        approved_by=approval.approved_by,
                        agent_id=self.config.agent_id,
                        duration_ms=duration_ms,
                    )
                return await func(*args, **kwargs)

            if approval.is_denied:
                if self.audit_logger:
                    self.audit_logger.log_approval_denied(
                        function_name=function_name,
                        parameters=params,
                        action_id=approval.action_id,
                        approved_by=approval.approved_by,
                        reason=approval.reason,
                        agent_id=self.config.agent_id,
                        duration_ms=duration_ms,
                    )
                raise SentinelBlockedError(
                    reason=approval.reason or "Approval denied",
                    action=function_name,
                    agent_id=self.config.agent_id,
                )

            if approval.is_timeout:
                if self.audit_logger:
                    self.audit_logger.log_approval_timeout(
                        function_name=function_name,
                        parameters=params,
                        action_id=approval.action_id,
                        agent_id=self.config.agent_id,
                        duration_ms=duration_ms,
                    )
                if self.config.fail_mode == "secure":
                    timeout = approval.timeout_seconds or self.config.timeout_seconds
                    raise SentinelTimeoutError(
                        action=function_name,
                        timeout_seconds=timeout,
                    )
                else:
                    logger.warning(
                        "Fail-safe mode: allowing action after timeout"
                    )
                    return await func(*args, **kwargs)

            # Error or unknown status
            if self.config.fail_mode == "secure":
                raise SentinelBlockedError(
                    reason="Approval error",
                    action=function_name,
                    agent_id=self.config.agent_id,
                )
            else:
                return await func(*args, **kwargs)

        # Default case (shouldn't reach here normally)
        return await func(*args, **kwargs)

    def execute_sync(
        self,
        func: Callable[P, T],
        *args: P.args,
        context_fn: Callable[[], dict[str, Any]] | None = None,
        **kwargs: P.kwargs,
    ) -> T:
        """Execute a sync function with governance checks.

        Wraps the sync execution in an async event loop.

        Args:
            func: The sync function to execute.
            *args: Positional arguments for the function.
            context_fn: Optional function to provide context for approval.
            **kwargs: Keyword arguments for the function.

        Returns:
            The function's return value if allowed.

        Raises:
            SentinelBlockedError: If the action is blocked.
            SentinelTimeoutError: If approval times out in secure mode.
        """
        start_time = time.perf_counter()
        function_name = func.__name__
        params = self._extract_params(func, args, kwargs)

        # Anomaly detection (if enabled)
        anomaly_result = None
        force_approval = False
        if self.anomaly_engine:
            try:
                # Get event loop or create one
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        # Cannot use run_until_complete in running loop
                        # Create new loop in thread for anomaly detection
                        import concurrent.futures
                        with concurrent.futures.ThreadPoolExecutor() as executor:
                            future = executor.submit(
                                asyncio.run,
                                self.anomaly_engine.analyze(
                                    function_name=function_name,
                                    parameters=params,
                                    agent_id=self.config.agent_id,
                                    context=self._get_context(context_fn),
                                )
                            )
                            anomaly_result = future.result(timeout=5)
                    else:
                        anomaly_result = loop.run_until_complete(
                            self.anomaly_engine.analyze(
                                function_name=function_name,
                                parameters=params,
                                agent_id=self.config.agent_id,
                                context=self._get_context(context_fn),
                            )
                        )
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    anomaly_result = loop.run_until_complete(
                        self.anomaly_engine.analyze(
                            function_name=function_name,
                            parameters=params,
                            agent_id=self.config.agent_id,
                            context=self._get_context(context_fn),
                        )
                    )

                # Always log anomaly analysis for visibility
                logger.info(
                    f"Anomaly analysis: {function_name} -> "
                    f"risk={anomaly_result.risk_score:.1f} ({anomaly_result.risk_level.name}), "
                    f"reasons={anomaly_result.reasons}"
                )

                # Log to audit when risk_score > 0
                if self.audit_logger and anomaly_result.risk_score > 0:
                    self.audit_logger.log_anomaly(
                        function_name=function_name,
                        parameters=params,
                        risk_score=anomaly_result.risk_score,
                        risk_level=anomaly_result.risk_level.name,
                        reasons=anomaly_result.reasons,
                        agent_id=self.config.agent_id,
                    )

                # Auto-block if risk is critical
                if anomaly_result.should_block:
                    duration_ms = (time.perf_counter() - start_time) * 1000
                    if self.audit_logger:
                        self.audit_logger.log_block(
                            function_name=function_name,
                            parameters=params,
                            rule_id="anomaly_detection",
                            reason=f"Anomaly detected: {', '.join(anomaly_result.reasons)}",
                            agent_id=self.config.agent_id,
                            duration_ms=duration_ms,
                        )
                    raise SentinelBlockedError(
                        reason=f"Anomaly detected (risk: {anomaly_result.risk_score:.1f}): {', '.join(anomaly_result.reasons)}",
                        action=function_name,
                        agent_id=self.config.agent_id,
                    )

                # Mark for forced approval if should_escalate
                if anomaly_result.should_escalate:
                    force_approval = True
            except SentinelBlockedError:
                raise
            except Exception as e:
                logger.warning(f"Anomaly detection error: {e}")
                # Continue with normal flow if anomaly detection fails

        try:
            result = self._evaluate(function_name, params)
        except Exception as e:
            logger.error(f"Error evaluating rules: {e}")
            if self.config.fail_mode == "secure":
                raise SentinelBlockedError(
                    reason=f"Rule evaluation error: {e}",
                    action=function_name,
                    agent_id=self.config.agent_id,
                ) from e
            else:
                logger.warning(
                    f"Fail-safe mode: allowing action despite error: {e}"
                )
                return func(*args, **kwargs)

        # Check if anomaly detection forces approval even if rules allow
        if result.is_allowed and not force_approval:
            duration_ms = (time.perf_counter() - start_time) * 1000
            if self.audit_logger:
                self.audit_logger.log_allow(
                    function_name=function_name,
                    parameters=params,
                    agent_id=self.config.agent_id,
                    duration_ms=duration_ms,
                )
            return func(*args, **kwargs)

        if result.is_blocked and not force_approval:
            duration_ms = (time.perf_counter() - start_time) * 1000
            if self.audit_logger:
                self.audit_logger.log_block(
                    function_name=function_name,
                    parameters=params,
                    rule_id=result.rule_id or "unknown",
                    reason=result.message or "Action blocked by policy",
                    agent_id=self.config.agent_id,
                    duration_ms=duration_ms,
                )
            raise SentinelBlockedError(
                reason=result.message or "Action blocked by policy",
                action=function_name,
                agent_id=self.config.agent_id,
            )

        if result.requires_approval or force_approval:
            # Get context only when approval is required
            context = self._get_context(context_fn)

            # Enhance message if forced by anomaly detection
            if force_approval and anomaly_result:
                enhanced_result = RuleResult(
                    action=RuleAction.REQUIRE_APPROVAL,
                    rule_id=result.rule_id or "anomaly_escalation",
                    message=f"Anomaly escalation (risk: {anomaly_result.risk_score:.1f}): {', '.join(anomaly_result.reasons)}",
                )
                approval_result = enhanced_result
            else:
                approval_result = result

            # Run approval in event loop
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            approval = loop.run_until_complete(
                self._handle_approval(function_name, params, approval_result, context)
            )

            # Log approval request
            if self.audit_logger:
                self.audit_logger.log_approval_requested(
                    function_name=function_name,
                    parameters=params,
                    action_id=approval.action_id,
                    rule_id=result.rule_id or "unknown",
                    context=context,
                    agent_id=self.config.agent_id,
                )

            duration_ms = (time.perf_counter() - start_time) * 1000

            if approval.is_approved:
                if self.audit_logger:
                    self.audit_logger.log_approval_granted(
                        function_name=function_name,
                        parameters=params,
                        action_id=approval.action_id,
                        approved_by=approval.approved_by,
                        agent_id=self.config.agent_id,
                        duration_ms=duration_ms,
                    )
                return func(*args, **kwargs)

            if approval.is_denied:
                if self.audit_logger:
                    self.audit_logger.log_approval_denied(
                        function_name=function_name,
                        parameters=params,
                        action_id=approval.action_id,
                        approved_by=approval.approved_by,
                        reason=approval.reason,
                        agent_id=self.config.agent_id,
                        duration_ms=duration_ms,
                    )
                raise SentinelBlockedError(
                    reason=approval.reason or "Approval denied",
                    action=function_name,
                    agent_id=self.config.agent_id,
                )

            if approval.is_timeout:
                if self.audit_logger:
                    self.audit_logger.log_approval_timeout(
                        function_name=function_name,
                        parameters=params,
                        action_id=approval.action_id,
                        agent_id=self.config.agent_id,
                        duration_ms=duration_ms,
                    )
                if self.config.fail_mode == "secure":
                    timeout = approval.timeout_seconds or self.config.timeout_seconds
                    raise SentinelTimeoutError(
                        action=function_name,
                        timeout_seconds=timeout,
                    )
                else:
                    logger.warning(
                        "Fail-safe mode: allowing action after timeout"
                    )
                    return func(*args, **kwargs)

            # Error or unknown status
            if self.config.fail_mode == "secure":
                raise SentinelBlockedError(
                    reason="Approval error",
                    action=function_name,
                    agent_id=self.config.agent_id,
                )
            else:
                return func(*args, **kwargs)

        # Default case
        return func(*args, **kwargs)


ContextFn = Callable[[], dict[str, Any]]


def protect(
    config: SentinelConfig,
    context_fn: ContextFn | None = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Decorator to protect a function with Sentinel governance.

    The decorated function will be intercepted before execution.
    Depending on configured rules, the function may be:
    - Allowed to execute normally
    - Blocked with SentinelBlockedError
    - Paused for human approval

    Works with both sync and async functions.

    Args:
        config: The Sentinel configuration.
        context_fn: Optional function that returns context dict for approvers.
            Called only when approval is required, not on every call.
            Context is shown to human approvers but NOT returned to the LLM.

    Returns:
        A decorator function.

    Example:
        >>> config = SentinelConfig(rules_path="rules.json")
        >>> @protect(config)
        ... async def transfer_funds(amount: float, destination: str) -> str:
        ...     return f"Transferred ${amount} to {destination}"

        >>> # With context function
        >>> @protect(config, context_fn=lambda: {"balance": get_balance()})
        ... async def transfer_funds(amount: float, destination: str) -> str:
        ...     return f"Transferred ${amount} to {destination}"
    """
    # Use cached wrapper if available to avoid duplicate evaluations
    config_id = id(config)
    if config_id not in _wrapper_cache:
        _wrapper_cache[config_id] = SentinelWrapper(config)
    wrapper = _wrapper_cache[config_id]

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                return await wrapper.execute_async(func, *args, context_fn=context_fn, **kwargs)

            return async_wrapper  # type: ignore
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
                return wrapper.execute_sync(func, *args, context_fn=context_fn, **kwargs)

            return sync_wrapper  # type: ignore

    return decorator
