"""LangChain integration for Sentinel.

Provides utilities to protect LangChain tools with Sentinel governance.

Usage:
    from sentinel.integrations.langchain import protect_tools, protect_tool

    # Protect all tools at once
    protected_tools = protect_tools(tools, config)

    # Or protect individual tool
    protected_search = protect_tool(search_tool, config)

Note:
    Context from context_fn is shown to human approvers only.
    It is NOT returned to the LLM agent - this is intentional for privacy.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from typing import Any, Callable, TypeVar

from sentinel.approval.base import ApprovalRequest
from sentinel.core.exceptions import SentinelBlockedError, SentinelTimeoutError
from sentinel.core.wrapper import SentinelConfig, SentinelWrapper, _wrapper_cache

logger = logging.getLogger(__name__)

# Type variable for generic tool types
T = TypeVar("T")

# Lazy import check for LangChain
_LANGCHAIN_AVAILABLE: bool | None = None
_BaseTool: type | None = None
_StructuredTool: type | None = None


def _check_langchain() -> None:
    """Check if LangChain is available and import required classes.

    Raises:
        ImportError: If langchain-core is not installed.
    """
    global _LANGCHAIN_AVAILABLE, _BaseTool, _StructuredTool

    if _LANGCHAIN_AVAILABLE is None:
        try:
            from langchain_core.tools import BaseTool, StructuredTool

            _LANGCHAIN_AVAILABLE = True
            _BaseTool = BaseTool
            _StructuredTool = StructuredTool
        except ImportError:
            _LANGCHAIN_AVAILABLE = False

    if not _LANGCHAIN_AVAILABLE:
        raise ImportError(
            "LangChain integration requires langchain-core. "
            "Install with: pip install sentinel[langchain]"
        )


def _get_wrapper(config: SentinelConfig) -> SentinelWrapper:
    """Get or create a SentinelWrapper for the config.

    Args:
        config: The Sentinel configuration.

    Returns:
        SentinelWrapper instance.
    """
    config_id = id(config)
    if config_id not in _wrapper_cache:
        _wrapper_cache[config_id] = SentinelWrapper(config)
    return _wrapper_cache[config_id]


def _execute_with_sentinel(
    wrapper: SentinelWrapper,
    tool_name: str,
    params: dict[str, Any],
    execute_fn: Callable[[], Any],
    context_fn: Callable[[], dict[str, Any]] | None = None,
) -> Any:
    """Execute a tool with Sentinel governance (sync version).

    Args:
        wrapper: The SentinelWrapper instance.
        tool_name: Name of the tool for rule matching.
        params: Tool parameters for rule evaluation.
        execute_fn: Function to execute if allowed.
        context_fn: Optional context function for approval.

    Returns:
        Result of execute_fn if allowed.

    Raises:
        SentinelBlockedError: If action is blocked.
    """
    start_time = time.perf_counter()
    config = wrapper.config

    try:
        result = wrapper.rules_engine.evaluate(tool_name, params)
    except Exception as e:
        logger.error(f"Error evaluating rules: {e}")
        if config.fail_mode == "secure":
            raise SentinelBlockedError(
                reason=f"Rule evaluation error: {e}",
                action=tool_name,
                agent_id=config.agent_id,
            ) from e
        else:
            return execute_fn()

    if result.is_allowed:
        duration_ms = (time.perf_counter() - start_time) * 1000
        if wrapper.audit_logger:
            wrapper.audit_logger.log_allow(
                function_name=tool_name,
                parameters=params,
                agent_id=config.agent_id,
                duration_ms=duration_ms,
            )
        return execute_fn()

    if result.is_blocked:
        duration_ms = (time.perf_counter() - start_time) * 1000
        if wrapper.audit_logger:
            wrapper.audit_logger.log_block(
                function_name=tool_name,
                parameters=params,
                rule_id=result.rule_id or "unknown",
                reason=result.message or "Action blocked by policy",
                agent_id=config.agent_id,
                duration_ms=duration_ms,
            )
        raise SentinelBlockedError(
            reason=result.message or "Action blocked by policy",
            action=tool_name,
            agent_id=config.agent_id,
        )

    if result.requires_approval:
        context = None
        if context_fn:
            try:
                context = context_fn()
            except Exception as e:
                logger.warning(f"Error calling context_fn: {e}")

        request = ApprovalRequest(
            function_name=tool_name,
            parameters=params,
            rule_id=result.rule_id or "unknown",
            message=result.message or "Approval required",
            agent_id=config.agent_id,
            context=context,
        )

        # Run approval synchronously
        try:
            loop = asyncio.new_event_loop()
            approval = loop.run_until_complete(
                wrapper.approval_interface.request_approval(request)
            )
            loop.close()
        except Exception as e:
            logger.error(f"Error requesting approval: {e}")
            if config.fail_mode == "secure":
                raise SentinelBlockedError(
                    reason=f"Approval error: {e}",
                    action=tool_name,
                    agent_id=config.agent_id,
                ) from e
            else:
                return execute_fn()

        if wrapper.audit_logger:
            wrapper.audit_logger.log_approval_requested(
                function_name=tool_name,
                parameters=params,
                action_id=approval.action_id,
                rule_id=result.rule_id or "unknown",
                context=context,
                agent_id=config.agent_id,
            )

        duration_ms = (time.perf_counter() - start_time) * 1000

        if approval.is_approved:
            if wrapper.audit_logger:
                wrapper.audit_logger.log_approval_granted(
                    function_name=tool_name,
                    parameters=params,
                    action_id=approval.action_id,
                    approved_by=approval.approved_by,
                    agent_id=config.agent_id,
                    duration_ms=duration_ms,
                )
            return execute_fn()

        if approval.is_denied:
            if wrapper.audit_logger:
                wrapper.audit_logger.log_approval_denied(
                    function_name=tool_name,
                    parameters=params,
                    action_id=approval.action_id,
                    approved_by=approval.approved_by,
                    reason=approval.reason,
                    agent_id=config.agent_id,
                    duration_ms=duration_ms,
                )
            raise SentinelBlockedError(
                reason=approval.reason or "Approval denied",
                action=tool_name,
                agent_id=config.agent_id,
            )

        if approval.is_timeout:
            if wrapper.audit_logger:
                wrapper.audit_logger.log_approval_timeout(
                    function_name=tool_name,
                    parameters=params,
                    action_id=approval.action_id,
                    agent_id=config.agent_id,
                    duration_ms=duration_ms,
                )
            if config.fail_mode == "secure":
                raise SentinelTimeoutError(
                    action=tool_name,
                    timeout_seconds=approval.timeout_seconds or config.timeout_seconds,
                )
            else:
                return execute_fn()

        # Error status
        if config.fail_mode == "secure":
            raise SentinelBlockedError(
                reason="Approval error",
                action=tool_name,
                agent_id=config.agent_id,
            )
        else:
            return execute_fn()

    return execute_fn()


async def _execute_with_sentinel_async(
    wrapper: SentinelWrapper,
    tool_name: str,
    params: dict[str, Any],
    execute_fn: Callable[[], Any],
    context_fn: Callable[[], dict[str, Any]] | None = None,
    is_async_fn: bool = False,
) -> Any:
    """Execute a tool with Sentinel governance (async version).

    Args:
        wrapper: The SentinelWrapper instance.
        tool_name: Name of the tool for rule matching.
        params: Tool parameters for rule evaluation.
        execute_fn: Function to execute if allowed.
        context_fn: Optional context function for approval.
        is_async_fn: Whether execute_fn is async.

    Returns:
        Result of execute_fn if allowed.

    Raises:
        SentinelBlockedError: If action is blocked.
    """
    start_time = time.perf_counter()
    config = wrapper.config

    try:
        result = wrapper.rules_engine.evaluate(tool_name, params)
    except Exception as e:
        logger.error(f"Error evaluating rules: {e}")
        if config.fail_mode == "secure":
            raise SentinelBlockedError(
                reason=f"Rule evaluation error: {e}",
                action=tool_name,
                agent_id=config.agent_id,
            ) from e
        else:
            if is_async_fn:
                return await execute_fn()
            return execute_fn()

    if result.is_allowed:
        duration_ms = (time.perf_counter() - start_time) * 1000
        if wrapper.audit_logger:
            wrapper.audit_logger.log_allow(
                function_name=tool_name,
                parameters=params,
                agent_id=config.agent_id,
                duration_ms=duration_ms,
            )
        if is_async_fn:
            return await execute_fn()
        return execute_fn()

    if result.is_blocked:
        duration_ms = (time.perf_counter() - start_time) * 1000
        if wrapper.audit_logger:
            wrapper.audit_logger.log_block(
                function_name=tool_name,
                parameters=params,
                rule_id=result.rule_id or "unknown",
                reason=result.message or "Action blocked by policy",
                agent_id=config.agent_id,
                duration_ms=duration_ms,
            )
        raise SentinelBlockedError(
            reason=result.message or "Action blocked by policy",
            action=tool_name,
            agent_id=config.agent_id,
        )

    if result.requires_approval:
        context = None
        if context_fn:
            try:
                context = context_fn()
            except Exception as e:
                logger.warning(f"Error calling context_fn: {e}")

        request = ApprovalRequest(
            function_name=tool_name,
            parameters=params,
            rule_id=result.rule_id or "unknown",
            message=result.message or "Approval required",
            agent_id=config.agent_id,
            context=context,
        )

        approval = await wrapper.approval_interface.request_approval(request)

        if wrapper.audit_logger:
            wrapper.audit_logger.log_approval_requested(
                function_name=tool_name,
                parameters=params,
                action_id=approval.action_id,
                rule_id=result.rule_id or "unknown",
                context=context,
                agent_id=config.agent_id,
            )

        duration_ms = (time.perf_counter() - start_time) * 1000

        if approval.is_approved:
            if wrapper.audit_logger:
                wrapper.audit_logger.log_approval_granted(
                    function_name=tool_name,
                    parameters=params,
                    action_id=approval.action_id,
                    approved_by=approval.approved_by,
                    agent_id=config.agent_id,
                    duration_ms=duration_ms,
                )
            if is_async_fn:
                return await execute_fn()
            return execute_fn()

        if approval.is_denied:
            if wrapper.audit_logger:
                wrapper.audit_logger.log_approval_denied(
                    function_name=tool_name,
                    parameters=params,
                    action_id=approval.action_id,
                    approved_by=approval.approved_by,
                    reason=approval.reason,
                    agent_id=config.agent_id,
                    duration_ms=duration_ms,
                )
            raise SentinelBlockedError(
                reason=approval.reason or "Approval denied",
                action=tool_name,
                agent_id=config.agent_id,
            )

        if approval.is_timeout:
            if wrapper.audit_logger:
                wrapper.audit_logger.log_approval_timeout(
                    function_name=tool_name,
                    parameters=params,
                    action_id=approval.action_id,
                    agent_id=config.agent_id,
                    duration_ms=duration_ms,
                )
            if config.fail_mode == "secure":
                raise SentinelTimeoutError(
                    action=tool_name,
                    timeout_seconds=approval.timeout_seconds or config.timeout_seconds,
                )
            else:
                if is_async_fn:
                    return await execute_fn()
                return execute_fn()

        # Error status
        if config.fail_mode == "secure":
            raise SentinelBlockedError(
                reason="Approval error",
                action=tool_name,
                agent_id=config.agent_id,
            )
        else:
            if is_async_fn:
                return await execute_fn()
            return execute_fn()

    if is_async_fn:
        return await execute_fn()
    return execute_fn()


def protect_tool(
    tool: T,
    config: SentinelConfig,
    context_fn: Callable[[], dict[str, Any]] | None = None,
) -> T:
    """Wrap a single LangChain tool with Sentinel protection.

    The protected tool will be subject to Sentinel governance rules.
    When a rule requires approval, the context_fn (if provided) will be
    called to gather context for the human approver.

    Args:
        tool: LangChain BaseTool instance.
        config: SentinelConfig with rules and approval interface.
        context_fn: Optional function to provide context for approval.
            Called only when approval is required, not on every call.
            Context is shown to human approvers but NOT returned to the LLM.

    Returns:
        New BaseTool with Sentinel protection applied.

    Raises:
        ImportError: If langchain-core is not installed.

    Example:
        >>> from sentinel.integrations.langchain import protect_tool
        >>> protected = protect_tool(search_tool, config)
    """
    _check_langchain()

    # Get the wrapper
    wrapper = _get_wrapper(config)

    # Get original tool attributes
    tool_name = tool.name  # type: ignore
    tool_description = tool.description  # type: ignore
    tool_args_schema = getattr(tool, "args_schema", None)
    tool_return_direct = getattr(tool, "return_direct", False)

    # Get the original function from the tool
    # StructuredTool stores the original function in `func` attribute
    original_func = getattr(tool, "func", None)
    original_coroutine = getattr(tool, "coroutine", None)

    # Check if we have access to the original function
    if original_func is None:
        # Fallback: use _run/_arun but they require extra args
        original_func = tool._run  # type: ignore

    # Check if original has async implementation
    has_async = original_coroutine is not None and inspect.iscoroutinefunction(original_coroutine)

    # Create new tool class with protected methods
    class ProtectedTool(_BaseTool):  # type: ignore
        """Sentinel-protected LangChain tool."""

        name: str = tool_name
        description: str = tool_description

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            # Extract params from kwargs (LangChain passes tool args as kwargs)
            params = dict(kwargs)
            return _execute_with_sentinel(
                wrapper=wrapper,
                tool_name=tool_name,
                params=params,
                execute_fn=lambda: original_func(*args, **kwargs),
                context_fn=context_fn,
            )

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            params = dict(kwargs)
            if has_async and original_coroutine is not None:
                return await _execute_with_sentinel_async(
                    wrapper=wrapper,
                    tool_name=tool_name,
                    params=params,
                    execute_fn=lambda: original_coroutine(*args, **kwargs),
                    context_fn=context_fn,
                    is_async_fn=True,
                )
            else:
                return await _execute_with_sentinel_async(
                    wrapper=wrapper,
                    tool_name=tool_name,
                    params=params,
                    execute_fn=lambda: original_func(*args, **kwargs),
                    context_fn=context_fn,
                    is_async_fn=False,
                )

    # Copy args_schema if present
    if tool_args_schema is not None:
        ProtectedTool.args_schema = tool_args_schema

    # Create and configure instance
    protected = ProtectedTool()
    protected.return_direct = tool_return_direct

    return protected  # type: ignore


def protect_tools(
    tools: list[T],
    config: SentinelConfig,
    context_fn: Callable[[], dict[str, Any]] | None = None,
) -> list[T]:
    """Wrap multiple LangChain tools with Sentinel protection.

    This is a convenience function that applies protect_tool to each
    tool in the list. All tools share the same config and context_fn.

    Args:
        tools: List of LangChain tools.
        config: SentinelConfig (shared across all tools).
        context_fn: Optional context function (shared across all tools).
            Called only when approval is required, not on every call.
            Context is shown to human approvers but NOT returned to the LLM.

    Returns:
        List of protected tools (same order as input).

    Raises:
        ImportError: If langchain-core is not installed.

    Example:
        >>> from sentinel.integrations.langchain import protect_tools
        >>> protected = protect_tools([search, calculator], config)
    """
    _check_langchain()
    return [protect_tool(t, config, context_fn) for t in tools]


def create_protected_tool(
    func: Callable[..., Any],
    config: SentinelConfig,
    name: str | None = None,
    description: str | None = None,
    context_fn: Callable[[], dict[str, Any]] | None = None,
    return_direct: bool = False,
) -> Any:
    """Create a new protected LangChain tool from a function.

    Combines @tool decorator with @protect in one step. This is useful
    when creating new tools that should be protected from the start.

    Args:
        func: The function to wrap as a tool.
        config: SentinelConfig with rules and approval interface.
        name: Tool name (defaults to function name).
        description: Tool description (defaults to function docstring).
        context_fn: Optional function to provide context for approval.
            Called only when approval is required, not on every call.
            Context is shown to human approvers but NOT returned to the LLM.
        return_direct: Whether to return tool output directly to user.

    Returns:
        A new protected BaseTool instance.

    Raises:
        ImportError: If langchain-core is not installed.

    Example:
        >>> def search(query: str) -> str:
        ...     '''Search the web for information.'''
        ...     return f"Results for: {query}"
        >>> protected_search = create_protected_tool(search, config)
    """
    _check_langchain()

    # Get wrapper
    wrapper = _get_wrapper(config)

    # Determine tool attributes
    tool_name = name or func.__name__
    tool_description = description or func.__doc__ or "No description provided."

    # Check if function is async
    is_async = inspect.iscoroutinefunction(func)

    # Create tool class
    class ProtectedTool(_BaseTool):  # type: ignore
        """Sentinel-protected LangChain tool created from function."""

        name: str = tool_name
        description: str = tool_description

        def _run(self, *args: Any, **kwargs: Any) -> Any:
            if is_async:
                raise RuntimeError(
                    f"Tool '{tool_name}' is async. Use await or call _arun."
                )
            params = dict(kwargs)
            return _execute_with_sentinel(
                wrapper=wrapper,
                tool_name=tool_name,
                params=params,
                execute_fn=lambda: func(*args, **kwargs),
                context_fn=context_fn,
            )

        async def _arun(self, *args: Any, **kwargs: Any) -> Any:
            params = dict(kwargs)
            if is_async:
                return await _execute_with_sentinel_async(
                    wrapper=wrapper,
                    tool_name=tool_name,
                    params=params,
                    execute_fn=lambda: func(*args, **kwargs),
                    context_fn=context_fn,
                    is_async_fn=True,
                )
            else:
                return await _execute_with_sentinel_async(
                    wrapper=wrapper,
                    tool_name=tool_name,
                    params=params,
                    execute_fn=lambda: func(*args, **kwargs),
                    context_fn=context_fn,
                    is_async_fn=False,
                )

    # Try to infer args_schema from function signature
    try:
        from pydantic import create_model

        sig = inspect.signature(func)
        fields: dict[str, Any] = {}
        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue
            annotation = param.annotation if param.annotation != inspect.Parameter.empty else Any
            default = param.default if param.default != inspect.Parameter.empty else ...
            fields[param_name] = (annotation, default)

        if fields:
            ToolInput = create_model(f"{tool_name}Input", **fields)  # type: ignore
            ProtectedTool.args_schema = ToolInput
    except Exception as e:
        # If schema inference fails (e.g., Python 3.14 pydantic issues), continue without it
        logger.debug(f"Could not infer args_schema: {e}")

    # Create instance
    protected = ProtectedTool()
    protected.return_direct = return_direct

    return protected
