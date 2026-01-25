"""Tests for anomaly detection module.

Tests the statistical detector, LLM auditor, and anomaly engine.
"""

import json
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.anomaly.detector import (
    AnomalyDetector,
    AnomalyEngine,
    AnomalyResult,
    RiskLevel,
)
from sentinel.anomaly.statistical import StatisticalDetector


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_from_score_low(self):
        """Test LOW risk level for scores 0-3."""
        assert RiskLevel.from_score(0.0) == RiskLevel.LOW
        assert RiskLevel.from_score(2.5) == RiskLevel.LOW
        assert RiskLevel.from_score(3.9) == RiskLevel.LOW

    def test_from_score_medium(self):
        """Test MEDIUM risk level for scores 4-6."""
        assert RiskLevel.from_score(4.0) == RiskLevel.MEDIUM
        assert RiskLevel.from_score(5.5) == RiskLevel.MEDIUM
        assert RiskLevel.from_score(6.9) == RiskLevel.MEDIUM

    def test_from_score_high(self):
        """Test HIGH risk level for scores 7-8."""
        assert RiskLevel.from_score(7.0) == RiskLevel.HIGH
        assert RiskLevel.from_score(8.0) == RiskLevel.HIGH
        assert RiskLevel.from_score(8.9) == RiskLevel.HIGH

    def test_from_score_critical(self):
        """Test CRITICAL risk level for scores 9-10."""
        assert RiskLevel.from_score(9.0) == RiskLevel.CRITICAL
        assert RiskLevel.from_score(10.0) == RiskLevel.CRITICAL


class TestAnomalyResult:
    """Tests for AnomalyResult dataclass."""

    def test_create_result(self):
        """Test creating an anomaly result."""
        result = AnomalyResult(
            risk_score=5.5,
            risk_level=RiskLevel.MEDIUM,
            reasons=["High transaction amount"],
            should_escalate=False,
            should_block=False,
            detector_type="statistical",
            confidence=0.8,
        )

        assert result.risk_score == 5.5
        assert result.risk_level == RiskLevel.MEDIUM
        assert len(result.reasons) == 1
        assert result.detector_type == "statistical"
        assert result.confidence == 0.8

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = AnomalyResult(
            risk_score=7.5,
            risk_level=RiskLevel.HIGH,
            reasons=["Unusual time", "High value"],
            should_escalate=True,
            should_block=False,
            detector_type="statistical",
            confidence=0.9,
            metadata={"samples": 100},
        )

        data = result.to_dict()

        assert data["risk_score"] == 7.5
        assert data["risk_level"] == "HIGH"
        assert len(data["reasons"]) == 2
        assert data["should_escalate"] is True
        assert data["should_block"] is False
        assert data["metadata"]["samples"] == 100


class TestStatisticalDetector:
    """Tests for StatisticalDetector."""

    @pytest.fixture
    def log_dir(self, tmp_path):
        """Create temporary log directory."""
        log_dir = tmp_path / "sentinel_logs"
        log_dir.mkdir()
        return log_dir

    @pytest.fixture
    def detector(self, log_dir):
        """Create detector with temporary log directory."""
        return StatisticalDetector(
            log_dir=log_dir,
            lookback_days=30,
            min_samples=3,
        )

    def _create_log_entry(
        self,
        function_name: str,
        parameters: dict,
        agent_id: str = "test-agent",
        hours_ago: int = 0,
    ) -> dict:
        """Create a log entry for testing."""
        timestamp = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        return {
            "timestamp": timestamp.isoformat(),
            "event_type": "allow",
            "function_name": function_name,
            "parameters": parameters,
            "result": "executed",
            "agent_id": agent_id,
        }

    def _write_logs(self, log_dir: Path, entries: list[dict]) -> None:
        """Write log entries to a file."""
        log_file = log_dir / f"audit_{datetime.now().date().isoformat()}.jsonl"
        with open(log_file, "w") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

    @pytest.mark.asyncio
    async def test_insufficient_history(self, detector):
        """Test detector returns low risk with insufficient history."""
        result = await detector.analyze(
            function_name="transfer_funds",
            parameters={"amount": 1000},
            agent_id="test-agent",
        )

        assert result.risk_score == 0.0
        assert result.risk_level == RiskLevel.LOW
        assert "Insufficient history" in result.reasons[0]
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_normal_value(self, detector, log_dir):
        """Test detector returns low risk for normal values."""
        # Create history with similar values
        entries = [
            self._create_log_entry("transfer_funds", {"amount": 100}, hours_ago=i * 2)
            for i in range(10)
        ]
        self._write_logs(log_dir, entries)

        # Invalidate cache
        detector.invalidate_cache()

        result = await detector.analyze(
            function_name="transfer_funds",
            parameters={"amount": 100},
            agent_id="test-agent",
        )

        assert result.risk_score == 0.0
        assert result.risk_level == RiskLevel.LOW

    @pytest.mark.asyncio
    async def test_anomalous_value(self, detector, log_dir):
        """Test detector flags anomalous values."""
        # Create history with small values
        entries = [
            self._create_log_entry("transfer_funds", {"amount": 50 + i * 5}, hours_ago=i * 2)
            for i in range(10)
        ]
        self._write_logs(log_dir, entries)

        # Invalidate cache
        detector.invalidate_cache()

        # Test with a much larger value
        result = await detector.analyze(
            function_name="transfer_funds",
            parameters={"amount": 5000},
            agent_id="test-agent",
        )

        assert result.risk_score > 0
        assert "standard deviations" in str(result.reasons) or "unusual" in str(result.reasons)

    @pytest.mark.asyncio
    async def test_z_score_calculation(self, detector):
        """Test Z-score calculation."""
        historical = [10, 20, 30, 40, 50]

        # Value at mean should have z-score of 0
        z_score = detector._calculate_z_score(30, historical)
        assert abs(z_score) < 0.1  # Close to 0

        # Value far from mean should have high z-score
        z_score_high = detector._calculate_z_score(100, historical)
        assert z_score_high > 3

    def test_z_score_with_zero_stdev(self, detector):
        """Test Z-score when all values are the same."""
        historical = [50, 50, 50, 50, 50]

        # Same value should return 0
        z_score = detector._calculate_z_score(50, historical)
        assert z_score == 0.0

        # Different value should return high score
        z_score = detector._calculate_z_score(51, historical)
        assert z_score == 10.0

    @pytest.mark.asyncio
    async def test_new_parameter_detection(self, detector, log_dir):
        """Test detection of new parameter values."""
        # Create history with known destinations
        entries = [
            self._create_log_entry("transfer_funds", {"destination": "user1@example.com", "amount": 100}, hours_ago=i)
            for i in range(5)
        ]
        entries.extend([
            self._create_log_entry("transfer_funds", {"destination": "user2@example.com", "amount": 100}, hours_ago=i + 5)
            for i in range(5)
        ])
        entries.extend([
            self._create_log_entry("transfer_funds", {"destination": "user3@example.com", "amount": 100}, hours_ago=i + 10)
            for i in range(5)
        ])
        self._write_logs(log_dir, entries)

        detector.invalidate_cache()

        # Test with new destination
        result = await detector.analyze(
            function_name="transfer_funds",
            parameters={"destination": "new_user@example.com", "amount": 100},
            agent_id="test-agent",
        )

        assert "new_values" in result.metadata or result.risk_score >= 4.0

    @pytest.mark.asyncio
    async def test_cache_invalidation(self, detector, log_dir):
        """Test cache invalidation method works.

        Note: Caching is currently DISABLED in StatisticalDetector
        to ensure fresh reads of newly logged events. The invalidate_cache
        method still works but has no effect since caching is off.
        """
        # Create initial history
        entries = [
            self._create_log_entry("func", {"x": i}, hours_ago=i)
            for i in range(5)
        ]
        self._write_logs(log_dir, entries)

        # First call loads history (but doesn't cache since caching is disabled)
        await detector.analyze(
            function_name="func",
            parameters={"x": 3},
            agent_id="test-agent",
        )

        # With caching disabled, cache should be empty
        # This is expected behavior - we disabled caching to fix
        # the bug where newly logged events weren't being seen
        assert len(detector._cache) == 0

        # Invalidate cache (should work even with empty cache)
        detector.invalidate_cache()

        # Verify cache is still empty
        assert len(detector._cache) == 0


class TestAnomalyEngine:
    """Tests for AnomalyEngine."""

    @pytest.fixture
    def log_dir(self, tmp_path):
        """Create temporary log directory."""
        log_dir = tmp_path / "sentinel_logs"
        log_dir.mkdir()
        return log_dir

    def test_no_detectors(self):
        """Test engine with no detectors enabled."""
        engine = AnomalyEngine(
            statistical_enabled=False,
            llm_enabled=False,
        )

        assert len(engine.detectors) == 0

    def test_statistical_enabled(self, log_dir):
        """Test engine with statistical detector enabled."""
        engine = AnomalyEngine(
            statistical_enabled=True,
            llm_enabled=False,
            log_dir=str(log_dir),
        )

        assert len(engine.detectors) == 1
        assert isinstance(engine.detectors[0], StatisticalDetector)

    @pytest.mark.asyncio
    async def test_analyze_no_detectors(self):
        """Test analyze with no detectors returns low risk."""
        engine = AnomalyEngine(
            statistical_enabled=False,
            llm_enabled=False,
        )

        result = await engine.analyze(
            function_name="test",
            parameters={},
        )

        assert result.risk_score == 0.0
        assert result.risk_level == RiskLevel.LOW
        assert "No detectors enabled" in result.reasons

    @pytest.mark.asyncio
    async def test_analyze_combines_results(self, log_dir):
        """Test that engine combines detector results."""
        engine = AnomalyEngine(
            statistical_enabled=True,
            llm_enabled=False,
            log_dir=str(log_dir),
        )

        result = await engine.analyze(
            function_name="test",
            parameters={"amount": 100},
            agent_id="test-agent",
        )

        # Should run without error
        assert result.risk_level in RiskLevel
        assert result.detector_type in ["statistical", "none"]

    @pytest.mark.asyncio
    async def test_escalation_threshold(self, log_dir):
        """Test escalation threshold application."""
        engine = AnomalyEngine(
            statistical_enabled=True,
            llm_enabled=False,
            escalation_threshold=7.0,
            block_threshold=9.0,
            log_dir=str(log_dir),
        )

        # Mock detector result
        mock_result = AnomalyResult(
            risk_score=7.5,
            risk_level=RiskLevel.HIGH,
            reasons=["Test reason"],
            should_escalate=False,  # Will be overridden
            should_block=False,
            detector_type="statistical",
            confidence=0.8,
        )

        with patch.object(engine.detectors[0], 'analyze', return_value=mock_result):
            result = await engine.analyze(
                function_name="test",
                parameters={},
            )

        assert result.should_escalate is True
        assert result.should_block is False

    @pytest.mark.asyncio
    async def test_block_threshold(self, log_dir):
        """Test block threshold application."""
        engine = AnomalyEngine(
            statistical_enabled=True,
            llm_enabled=False,
            escalation_threshold=7.0,
            block_threshold=9.0,
            log_dir=str(log_dir),
        )

        # Mock detector result
        mock_result = AnomalyResult(
            risk_score=9.5,
            risk_level=RiskLevel.CRITICAL,
            reasons=["Critical anomaly"],
            should_escalate=False,
            should_block=False,
            detector_type="statistical",
            confidence=0.9,
        )

        with patch.object(engine.detectors[0], 'analyze', return_value=mock_result):
            result = await engine.analyze(
                function_name="test",
                parameters={},
            )

        assert result.should_escalate is True
        assert result.should_block is True

    @pytest.mark.asyncio
    async def test_detector_error_handling(self, log_dir):
        """Test that engine handles detector errors gracefully."""
        engine = AnomalyEngine(
            statistical_enabled=True,
            llm_enabled=False,
            log_dir=str(log_dir),
        )

        # Mock detector to raise an exception
        with patch.object(engine.detectors[0], 'analyze', side_effect=Exception("Test error")):
            result = await engine.analyze(
                function_name="test",
                parameters={},
            )

        # Should return low risk result with error info
        assert result.risk_score == 0.0
        assert "error" in str(result.reasons).lower()


class TestLLMAuditorDetector:
    """Tests for LLMAuditorDetector."""

    def test_import_llm_auditor(self):
        """Test that LLM auditor can be imported."""
        from sentinel.anomaly.llm_auditor import LLMAuditorDetector

        detector = LLMAuditorDetector(
            provider="openai",
            model="gpt-4o-mini",
        )

        assert detector.provider == "openai"
        assert detector.model == "gpt-4o-mini"

    def test_build_prompt(self):
        """Test prompt building."""
        from sentinel.anomaly.llm_auditor import LLMAuditorDetector

        detector = LLMAuditorDetector()

        prompt = detector._build_prompt(
            function_name="transfer_funds",
            parameters={"amount": 1000, "destination": "user@example.com"},
            agent_id="test-agent",
            context={"balance": 5000},
        )

        assert "transfer_funds" in prompt
        assert "1000" in prompt
        assert "test-agent" in prompt
        assert "5000" in prompt
        assert "JSON" in prompt

    def test_build_prompt_redacts_secrets(self):
        """Test that secrets are redacted in prompt."""
        from sentinel.anomaly.llm_auditor import LLMAuditorDetector

        detector = LLMAuditorDetector()

        prompt = detector._build_prompt(
            function_name="api_call",
            parameters={"api_key": "secret123", "data": "test"},
            agent_id=None,
            context=None,
        )

        assert "secret123" not in prompt
        assert "[REDACTED]" in prompt

    def test_parse_valid_response(self):
        """Test parsing valid JSON response."""
        from sentinel.anomaly.llm_auditor import LLMAuditorDetector

        detector = LLMAuditorDetector()

        response = '''{"risk_score": 5.5, "reasons": ["Unusual amount"], "recommendation": "review"}'''

        result = detector._parse_response(response)

        assert result.risk_score == 5.5
        assert "Unusual amount" in result.reasons
        assert result.should_escalate is True
        assert result.should_block is False

    def test_parse_markdown_response(self):
        """Test parsing response wrapped in markdown code block."""
        from sentinel.anomaly.llm_auditor import LLMAuditorDetector

        detector = LLMAuditorDetector()

        response = '''```json
{"risk_score": 8.0, "reasons": ["High risk"], "recommendation": "block"}
```'''

        result = detector._parse_response(response)

        assert result.risk_score == 8.0
        assert result.should_block is True

    def test_parse_invalid_response(self):
        """Test handling invalid JSON response."""
        from sentinel.anomaly.llm_auditor import LLMAuditorDetector

        detector = LLMAuditorDetector()

        response = "This is not valid JSON"

        result = detector._parse_response(response)

        assert result.risk_score == 0.0
        assert result.confidence == 0.0
        assert "parse_error" in result.metadata

    @pytest.mark.asyncio
    async def test_analyze_without_api_key(self):
        """Test that analyze fails gracefully without API key."""
        from sentinel.anomaly.llm_auditor import LLMAuditorDetector

        detector = LLMAuditorDetector(
            provider="openai",
            api_key=None,
        )

        # Clear any env vars
        with patch.dict('os.environ', {}, clear=True):
            result = await detector.analyze(
                function_name="test",
                parameters={},
            )

        # Should fail gracefully
        assert result.risk_score == 0.0
        assert "error" in result.metadata or "failed" in str(result.reasons).lower()


class TestAnomalyIntegration:
    """Integration tests for anomaly detection with SentinelConfig."""

    @pytest.fixture
    def rules_file(self, tmp_path):
        """Create a test rules file."""
        rules_content = {
            "version": "1.0",
            "default_action": "allow",
            "rules": []
        }
        rules_path = tmp_path / "rules.json"
        with open(rules_path, "w") as f:
            json.dump(rules_content, f)
        return rules_path

    def test_config_with_anomaly_detection(self, rules_file, tmp_path):
        """Test SentinelConfig with anomaly detection enabled."""
        from sentinel import SentinelConfig

        config = SentinelConfig(
            rules_path=rules_file,
            anomaly_detection=True,
            anomaly_statistical=True,
            anomaly_llm=False,
            anomaly_escalation_threshold=7.0,
            anomaly_block_threshold=9.0,
            audit_log=True,
            audit_log_dir=tmp_path / "logs",
        )

        assert config.anomaly_detection is True
        assert config.get_anomaly_engine() is not None

    def test_config_without_anomaly_detection(self, rules_file):
        """Test SentinelConfig with anomaly detection disabled."""
        from sentinel import SentinelConfig

        config = SentinelConfig(
            rules_path=rules_file,
            anomaly_detection=False,
        )

        assert config.anomaly_detection is False
        assert config.get_anomaly_engine() is None
