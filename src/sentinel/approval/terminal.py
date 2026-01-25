"""Terminal-based approval interface for Sentinel.

This module provides an approval interface that prompts the user
in the terminal for approval decisions. It's primarily intended
for development and testing, but can also be used for CLI tools.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

from sentinel.approval.base import (
    ApprovalInterface,
    ApprovalRequest,
    ApprovalResult,
    ApprovalStatus,
)


class TerminalApprovalInterface(ApprovalInterface):
    """Approval interface that prompts the user in the terminal.

    This interface displays the approval request in the terminal and
    waits for the user to approve or deny the action. It supports
    timeout handling and various input formats.

    Attributes:
        timeout_seconds: Maximum time to wait for user input.
    """

    # Valid inputs for approval
    YES_INPUTS = {"y", "yes"}
    NO_INPUTS = {"n", "no"}

    def __init__(self, timeout_seconds: float = 300) -> None:
        """Initialize the terminal approval interface.

        Args:
            timeout_seconds: Maximum time to wait for user input (default: 5 minutes).
        """
        self.timeout_seconds = timeout_seconds

    async def request_approval(self, request: ApprovalRequest) -> ApprovalResult:
        """Request approval from the user via terminal.

        Displays the approval request and prompts the user to approve
        or deny the action. Handles timeout and invalid input.

        Args:
            request: The approval request containing action details.

        Returns:
            ApprovalResult indicating the user's decision or timeout.
        """
        # Display the request
        display = self.format_request(request)
        print(display, file=sys.stderr)
        print("\nApprove this action? [y/n]: ", end="", file=sys.stderr, flush=True)

        try:
            # Try to get user input with timeout
            user_input = await asyncio.wait_for(
                self._get_user_input_async(),
                timeout=self.timeout_seconds,
            )

            # Parse the input
            normalized = user_input.strip().lower()

            while normalized not in self.YES_INPUTS and normalized not in self.NO_INPUTS:
                print(
                    "Invalid input. Please enter 'y' or 'n': ",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )
                user_input = await asyncio.wait_for(
                    self._get_user_input_async(),
                    timeout=self.timeout_seconds,
                )
                normalized = user_input.strip().lower()

            if normalized in self.YES_INPUTS:
                return ApprovalResult(
                    status=ApprovalStatus.APPROVED,
                    action_id=request.action_id or "",
                    approved_by="terminal_user",
                )
            else:
                return ApprovalResult(
                    status=ApprovalStatus.DENIED,
                    action_id=request.action_id or "",
                    approved_by="terminal_user",
                    reason="User denied the action",
                )

        except asyncio.TimeoutError:
            print("\nApproval request timed out.", file=sys.stderr)
            return ApprovalResult(
                status=ApprovalStatus.TIMEOUT,
                action_id=request.action_id or "",
                timeout_seconds=self.timeout_seconds,
            )

    async def _get_user_input_async(self) -> str:
        """Get user input asynchronously.

        Uses asyncio.to_thread to avoid blocking the event loop
        while waiting for user input.

        Returns:
            The user's input string.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._get_user_input)

    def _get_user_input(self) -> str:
        """Get user input from stdin.

        This method can be mocked in tests to simulate user input.

        Returns:
            The user's input string.
        """
        return input()

    def format_request(self, request: ApprovalRequest) -> str:
        """Format an approval request for terminal display.

        Creates a visually distinct block that clearly shows
        the action requiring approval and its parameters.

        Args:
            request: The approval request to format.

        Returns:
            A formatted string for terminal display.
        """
        lines = [
            "",
            "\033[1;33m" + "=" * 60 + "\033[0m",  # Yellow line
            "\033[1;33m SENTINEL APPROVAL REQUIRED \033[0m",
            "\033[1;33m" + "=" * 60 + "\033[0m",
            "",
        ]

        if request.agent_id:
            lines.append(f"\033[1mAgent:\033[0m {request.agent_id}")

        lines.extend([
            f"\033[1mFunction:\033[0m {request.function_name}",
            f"\033[1mRule:\033[0m {request.rule_id}",
            "",
            "\033[1mParameters:\033[0m",
        ])

        for key, value in request.parameters.items():
            # Truncate long values
            str_value = str(value)
            if len(str_value) > 50:
                str_value = str_value[:47] + "..."
            lines.append(f"  \033[36m{key}\033[0m: {str_value}")

        # Show context if provided (from context_fn)
        if request.context:
            lines.extend(["", "\033[1mContext:\033[0m"])
            for key, value in request.context.items():
                str_value = str(value)
                if len(str_value) > 50:
                    str_value = str_value[:47] + "..."
                lines.append(f"  \033[36m{key}\033[0m: {str_value}")

        lines.extend(
            [
                "",
                f"\033[1mReason:\033[0m {request.message}",
                "",
                "\033[1;33m" + "-" * 60 + "\033[0m",
            ]
        )

        return "\n".join(lines)
