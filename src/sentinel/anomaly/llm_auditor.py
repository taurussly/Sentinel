"""LLM-based anomaly detection (optional premium feature).

This detector uses Large Language Models to perform semantic analysis
of actions, identifying subtle patterns that statistical methods miss.

NOTE: This detector is OPTIONAL and disabled by default.
It adds latency (~500ms-2s) and API costs per call.

Recommended use cases:
- High-stakes transactions (> $1000)
- When statistical detector already flagged anomaly
- Periodic audit sampling
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from sentinel.anomaly.detector import AnomalyDetector, AnomalyResult, RiskLevel

logger = logging.getLogger(__name__)


class LLMAuditorDetector(AnomalyDetector):
    """Analyzes actions using LLM for semantic understanding.

    This detector calls an LLM API to evaluate the risk of an action
    based on semantic understanding of parameters and context.

    Attributes:
        provider: LLM provider ("openai" or "anthropic").
        model: Model to use for analysis.
        api_key: API key (if not in environment).
        max_tokens: Maximum tokens for response.
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o-mini",
        api_key: str | None = None,
        max_tokens: int = 500,
        timeout: float = 10.0,
    ):
        """Initialize the LLM auditor.

        Args:
            provider: "openai" or "anthropic".
            model: Model identifier.
            api_key: API key (uses env var if not provided).
            max_tokens: Max response tokens.
            timeout: Request timeout in seconds.
        """
        self.provider = provider
        self.model = model
        self.api_key = api_key
        self.max_tokens = max_tokens
        self.timeout = timeout
        self._client: Any = None

    async def analyze(
        self,
        function_name: str,
        parameters: dict[str, Any],
        agent_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> AnomalyResult:
        """Analyze action using LLM.

        Args:
            function_name: Name of the function.
            parameters: Function parameters.
            agent_id: Agent identifier.
            context: Additional context.

        Returns:
            AnomalyResult with LLM analysis.
        """
        try:
            # Build the prompt
            prompt = self._build_prompt(function_name, parameters, agent_id, context)

            # Call the LLM
            response = await self._call_llm(prompt)

            # Parse the response
            return self._parse_response(response)

        except Exception as e:
            logger.error(f"LLM auditor error: {e}")
            return AnomalyResult(
                risk_score=0.0,
                risk_level=RiskLevel.LOW,
                reasons=[f"LLM analysis failed: {str(e)}"],
                should_escalate=False,
                should_block=False,
                detector_type="llm",
                confidence=0.0,
                metadata={"error": str(e)},
            )

    def _build_prompt(
        self,
        function_name: str,
        parameters: dict[str, Any],
        agent_id: str | None,
        context: dict[str, Any] | None,
    ) -> str:
        """Build the analysis prompt for the LLM.

        Args:
            function_name: Function name.
            parameters: Parameters.
            agent_id: Agent ID.
            context: Context.

        Returns:
            Formatted prompt string.
        """
        # Sanitize parameters for display (limit length, remove sensitive data)
        safe_params = {}
        for k, v in parameters.items():
            str_v = str(v)
            if len(str_v) > 200:
                str_v = str_v[:200] + "..."
            # Mask potential secrets
            if any(secret in k.lower() for secret in ["password", "secret", "key", "token"]):
                str_v = "[REDACTED]"
            safe_params[k] = str_v

        safe_context = None
        if context:
            safe_context = {}
            for k, v in context.items():
                str_v = str(v)
                if len(str_v) > 200:
                    str_v = str_v[:200] + "..."
                safe_context[k] = str_v

        return f"""You are a security auditor for AI agents. Analyze this action and provide a risk assessment.

ACTION DETAILS:
- Function: {function_name}
- Agent ID: {agent_id or "unknown"}
- Parameters: {json.dumps(safe_params, indent=2)}
- Context: {json.dumps(safe_context, indent=2) if safe_context else "None provided"}

RESPOND IN JSON FORMAT ONLY:
{{
    "risk_score": <0.0 to 10.0>,
    "reasons": ["reason1", "reason2"],
    "recommendation": "allow" | "review" | "block"
}}

RISK GUIDELINES:
- 0-3: Normal operation, no concerns
- 4-6: Slightly unusual, worth logging
- 7-8: Anomalous, should require human review
- 9-10: Highly suspicious, should be blocked

Analyze for: unusual patterns, potential data exfiltration, excessive permissions, financial risk, compliance concerns, security vulnerabilities.

Important: Only output the JSON, no additional text."""

    async def _call_llm(self, prompt: str) -> str:
        """Call the LLM API.

        Args:
            prompt: The analysis prompt.

        Returns:
            LLM response text.
        """
        if self.provider == "openai":
            return await self._call_openai(prompt)
        elif self.provider == "anthropic":
            return await self._call_anthropic(prompt)
        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API.

        Args:
            prompt: The prompt.

        Returns:
            Response content.
        """
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for LLM auditor. "
                "Install with: pip install httpx"
            )

        api_key = self.api_key or os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OpenAI API key required. Set OPENAI_API_KEY env var or pass api_key."
            )

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a security auditor. Respond only in JSON format.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": self.max_tokens,
                    "temperature": 0.1,  # Low temperature for consistent analysis
                },
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]

    async def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic API.

        Args:
            prompt: The prompt.

        Returns:
            Response content.
        """
        try:
            import httpx
        except ImportError:
            raise ImportError(
                "httpx is required for LLM auditor. "
                "Install with: pip install httpx"
            )

        api_key = self.api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY env var or pass api_key."
            )

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "Content-Type": "application/json",
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": self.model,
                    "max_tokens": self.max_tokens,
                    "messages": [
                        {"role": "user", "content": prompt},
                    ],
                },
            )
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]

    def _parse_response(self, response: str) -> AnomalyResult:
        """Parse LLM response into AnomalyResult.

        Args:
            response: Raw LLM response.

        Returns:
            Parsed AnomalyResult.
        """
        try:
            # Try to extract JSON from response
            response = response.strip()

            # Handle markdown code blocks
            if response.startswith("```"):
                lines = response.split("\n")
                # Remove first and last lines (code block markers)
                json_lines = []
                in_block = False
                for line in lines:
                    if line.startswith("```") and not in_block:
                        in_block = True
                        continue
                    elif line.startswith("```") and in_block:
                        break
                    elif in_block:
                        json_lines.append(line)
                response = "\n".join(json_lines)

            data = json.loads(response)

            risk_score = float(data.get("risk_score", 0.0))
            risk_score = max(0.0, min(10.0, risk_score))  # Clamp to valid range

            reasons = data.get("reasons", [])
            if not isinstance(reasons, list):
                reasons = [str(reasons)]

            recommendation = data.get("recommendation", "allow")

            # Map recommendation to escalation/blocking
            should_escalate = recommendation in ["review", "block"]
            should_block = recommendation == "block"

            # Override based on score if recommendation is inconsistent
            if risk_score >= 9.0:
                should_block = True
                should_escalate = True
            elif risk_score >= 7.0:
                should_escalate = True

            return AnomalyResult(
                risk_score=risk_score,
                risk_level=RiskLevel.from_score(risk_score),
                reasons=reasons,
                should_escalate=should_escalate,
                should_block=should_block,
                detector_type="llm",
                confidence=0.8,  # LLM has high but not perfect confidence
                metadata={
                    "recommendation": recommendation,
                    "raw_response": response[:500],  # Truncate for storage
                },
            )

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            logger.warning(f"Failed to parse LLM response: {e}")
            return AnomalyResult(
                risk_score=0.0,
                risk_level=RiskLevel.LOW,
                reasons=[f"Failed to parse LLM response: {str(e)}"],
                should_escalate=False,
                should_block=False,
                detector_type="llm",
                confidence=0.0,
                metadata={"parse_error": str(e), "raw_response": response[:500]},
            )
