"""Webhook-based approval interface for Sentinel.

This module provides an approval interface that sends approval requests
to a webhook endpoint and polls for the response. This enables distributed
approval workflows where the agent runs on one server and approvals happen
elsewhere (mobile app, dashboard, Slack, etc.).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from sentinel.approval.base import (
    ApprovalInterface,
    ApprovalRequest,
    ApprovalResult,
    ApprovalStatus,
)


logger = logging.getLogger(__name__)


@dataclass
class WebhookConfig:
    """Configuration for the webhook approval interface.

    Attributes:
        webhook_url: URL for the initial POST request.
        status_url_template: URL template for polling, with {action_id} placeholder.
        token: Authentication token for X-Sentinel-Token header.
        timeout_seconds: Total timeout for approval (default: 300).
        poll_interval_seconds: Interval between status polls (default: 2).
        max_retries: Max retries for initial webhook POST (default: 3).
    """

    webhook_url: str
    status_url_template: str
    token: str
    timeout_seconds: float = 300
    poll_interval_seconds: float = 2
    max_retries: int = 3


class WebhookApprovalInterface(ApprovalInterface):
    """Approval interface that uses HTTP webhooks with polling.

    This interface sends approval requests to a webhook URL and polls
    a status endpoint for the response. It supports:
    - Retry with exponential backoff for initial POST
    - Async polling that doesn't block the event loop
    - Configurable timeout and poll intervals
    - Structured logging for debugging

    Example:
        >>> interface = WebhookApprovalInterface(
        ...     webhook_url="https://api.example.com/approval",
        ...     status_url_template="https://api.example.com/approval/{action_id}/status",
        ...     token="sk-sentinel-xxx",
        ... )
    """

    def __init__(
        self,
        webhook_url: str,
        status_url_template: str,
        token: str,
        timeout_seconds: float = 300,
        poll_interval_seconds: float = 2,
        max_retries: int = 3,
    ) -> None:
        """Initialize the webhook approval interface.

        Args:
            webhook_url: URL for the initial POST request.
            status_url_template: URL template for polling, with {action_id} placeholder.
            token: Authentication token for X-Sentinel-Token header.
            timeout_seconds: Total timeout for approval (default: 300).
            poll_interval_seconds: Interval between status polls (default: 2).
            max_retries: Max retries for initial webhook POST (default: 3).
        """
        self.config = WebhookConfig(
            webhook_url=webhook_url,
            status_url_template=status_url_template,
            token=token,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
            max_retries=max_retries,
        )
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create the HTTP client.

        Returns:
            The httpx async client.
        """
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _build_payload(self, request: ApprovalRequest) -> dict[str, Any]:
        """Build the JSON payload for the webhook POST.

        Args:
            request: The approval request.

        Returns:
            Dictionary payload for JSON serialization.
        """
        now = datetime.now(timezone.utc)
        timeout_at = datetime.fromtimestamp(
            now.timestamp() + self.config.timeout_seconds,
            tz=timezone.utc,
        )

        payload: dict[str, Any] = {
            "action_id": request.action_id,
            "agent_id": request.agent_id,
            "function_name": request.function_name,
            "rule_id": request.rule_id,
            "parameters": request.parameters,
            "reason": request.message,
            "timestamp": now.isoformat(),
            "timeout_at": timeout_at.isoformat(),
        }

        if request.context:
            payload["context"] = request.context

        return payload

    def _build_headers(self, action_id: str) -> dict[str, str]:
        """Build headers for HTTP requests.

        Args:
            action_id: The action ID for the request.

        Returns:
            Dictionary of HTTP headers.
        """
        return {
            "Content-Type": "application/json",
            "X-Sentinel-Token": self.config.token,
            "X-Sentinel-Action-ID": action_id,
        }

    async def _send_webhook(self, request: ApprovalRequest) -> bool:
        """Send the initial webhook POST with retry.

        Args:
            request: The approval request.

        Returns:
            True if the webhook was sent successfully, False otherwise.
        """
        client = await self._get_client()
        payload = self._build_payload(request)
        headers = self._build_headers(request.action_id or "")

        for attempt in range(self.config.max_retries):
            try:
                logger.debug(
                    f"Sending webhook attempt {attempt + 1}/{self.config.max_retries}",
                    extra={
                        "action_id": request.action_id,
                        "url": self.config.webhook_url,
                    },
                )

                response = await client.post(
                    self.config.webhook_url,
                    json=payload,
                    headers=headers,
                )

                if response.status_code in (200, 201, 202):
                    logger.info(
                        f"Webhook sent successfully",
                        extra={
                            "action_id": request.action_id,
                            "status_code": response.status_code,
                        },
                    )
                    return True

                logger.warning(
                    f"Webhook returned unexpected status",
                    extra={
                        "action_id": request.action_id,
                        "status_code": response.status_code,
                        "attempt": attempt + 1,
                    },
                )

            except httpx.RequestError as e:
                logger.warning(
                    f"Webhook request failed",
                    extra={
                        "action_id": request.action_id,
                        "error": str(e),
                        "attempt": attempt + 1,
                    },
                )

            # Exponential backoff: 1s, 2s, 4s
            if attempt < self.config.max_retries - 1:
                backoff = 2**attempt
                await asyncio.sleep(backoff)

        logger.error(
            f"All webhook retries failed",
            extra={"action_id": request.action_id},
        )
        return False

    async def _poll_status(self, action_id: str) -> ApprovalResult:
        """Poll the status endpoint until approval/denial/timeout.

        Args:
            action_id: The action ID to poll for.

        Returns:
            ApprovalResult with the final status.
        """
        client = await self._get_client()
        status_url = self.config.status_url_template.format(action_id=action_id)
        headers = self._build_headers(action_id)
        start_time = time.monotonic()
        end_time = start_time + self.config.timeout_seconds
        json_error_logged = False

        while True:
            now = time.monotonic()
            if now >= end_time:
                elapsed = now - start_time
                logger.warning(
                    "Approval polling timed out",
                    extra={"action_id": action_id, "elapsed": elapsed},
                )
                return ApprovalResult(
                    status=ApprovalStatus.TIMEOUT,
                    action_id=action_id,
                    timeout_seconds=self.config.timeout_seconds,
                )

            try:
                elapsed = now - start_time
                logger.debug(
                    "Polling for approval status",
                    extra={"action_id": action_id, "elapsed": elapsed},
                )

                response = await client.get(status_url, headers=headers)

                if response.status_code == 200:
                    try:
                        data = response.json()
                    except json.JSONDecodeError:
                        if not json_error_logged:
                            logger.warning(
                                "Status response is not valid JSON, treating as pending",
                                extra={
                                    "action_id": action_id,
                                    "content_type": response.headers.get("content-type"),
                                },
                            )
                            json_error_logged = True
                        await asyncio.sleep(self.config.poll_interval_seconds)
                        continue

                    status_str = data.get("status", "pending").lower()

                    if status_str == "approved":
                        logger.info(
                            "Approval granted",
                            extra={
                                "action_id": action_id,
                                "approved_by": data.get("approved_by"),
                            },
                        )
                        return ApprovalResult(
                            status=ApprovalStatus.APPROVED,
                            action_id=action_id,
                            approved_by=data.get("approved_by"),
                            reason=data.get("reason"),
                        )

                    elif status_str == "denied":
                        logger.info(
                            "Approval denied",
                            extra={
                                "action_id": action_id,
                                "approved_by": data.get("approved_by"),
                                "reason": data.get("reason"),
                            },
                        )
                        return ApprovalResult(
                            status=ApprovalStatus.DENIED,
                            action_id=action_id,
                            approved_by=data.get("approved_by"),
                            reason=data.get("reason"),
                        )

                    # status == "pending" - continue polling
                    logger.debug(
                        "Approval still pending",
                        extra={"action_id": action_id},
                    )

                elif response.status_code == 404:
                    logger.warning(
                        "Status endpoint returned 404",
                        extra={"action_id": action_id},
                    )

            except httpx.RequestError as e:
                logger.warning(
                    "Status poll failed",
                    extra={"action_id": action_id, "error": str(e)},
                )

            await asyncio.sleep(self.config.poll_interval_seconds)

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        """Request approval via webhook with polling.

        Sends the approval request to the webhook URL, then polls
        the status endpoint until approved, denied, or timeout.

        Args:
            request: The approval request containing action details.

        Returns:
            ApprovalResult indicating the final decision.
        """
        action_id = request.action_id or ""

        # Phase 1: Send the webhook
        webhook_sent = await self._send_webhook(request)

        if not webhook_sent:
            # Webhook failed - return error status
            return ApprovalResult(
                status=ApprovalStatus.ERROR,
                action_id=action_id,
                reason="Failed to send webhook after retries",
            )

        # Phase 2: Poll for response
        return await self._poll_status(action_id)

    def format_request(self, request: ApprovalRequest) -> str:
        """Format an approval request for logging.

        Args:
            request: The approval request to format.

        Returns:
            A formatted string representation.
        """
        lines = [
            "Webhook Approval Request",
            f"  Action ID: {request.action_id}",
            f"  Agent: {request.agent_id or 'N/A'}",
            f"  Function: {request.function_name}",
            f"  Rule: {request.rule_id}",
            f"  Reason: {request.message}",
        ]
        return "\n".join(lines)
