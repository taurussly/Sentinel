"""Tests for the WebhookApprovalInterface."""

import pytest
from unittest.mock import AsyncMock, patch
import httpx

from sentinel.approval.webhook import WebhookApprovalInterface
from sentinel.approval.base import ApprovalRequest, ApprovalStatus

from tests.mock_webhook_server import (
    create_webhook_response,
    create_status_response,
    MockApprovalState,
)


# Test configuration
WEBHOOK_URL = "https://api.example.com/approval"
STATUS_URL_TEMPLATE = "https://api.example.com/approval/{action_id}/status"
TOKEN = "sk-sentinel-test-token"


@pytest.fixture
def interface() -> WebhookApprovalInterface:
    """Create a webhook interface for testing."""
    return WebhookApprovalInterface(
        webhook_url=WEBHOOK_URL,
        status_url_template=STATUS_URL_TEMPLATE,
        token=TOKEN,
        timeout_seconds=5,
        poll_interval_seconds=0.1,
        max_retries=3,
    )


@pytest.fixture
def sample_request() -> ApprovalRequest:
    """Create a sample approval request."""
    return ApprovalRequest(
        action_id="test-action-123",
        agent_id="test-agent",
        function_name="transfer_funds",
        parameters={"amount": 500.0, "destination": "user@example.com"},
        rule_id="financial_limit",
        message="Transfer above $100 requires approval",
    )


class TestWebhookApprovalInterface:
    """Tests for WebhookApprovalInterface initialization and config."""

    def test_interface_creation(self) -> None:
        """Test creating the interface with config."""
        interface = WebhookApprovalInterface(
            webhook_url=WEBHOOK_URL,
            status_url_template=STATUS_URL_TEMPLATE,
            token=TOKEN,
        )
        assert interface.config.webhook_url == WEBHOOK_URL
        assert interface.config.status_url_template == STATUS_URL_TEMPLATE
        assert interface.config.token == TOKEN
        assert interface.config.timeout_seconds == 300
        assert interface.config.poll_interval_seconds == 2
        assert interface.config.max_retries == 3

    def test_interface_custom_config(self) -> None:
        """Test creating interface with custom config."""
        interface = WebhookApprovalInterface(
            webhook_url=WEBHOOK_URL,
            status_url_template=STATUS_URL_TEMPLATE,
            token=TOKEN,
            timeout_seconds=60,
            poll_interval_seconds=1,
            max_retries=5,
        )
        assert interface.config.timeout_seconds == 60
        assert interface.config.poll_interval_seconds == 1
        assert interface.config.max_retries == 5


class TestPayloadBuilding:
    """Tests for payload and header building."""

    def test_build_payload(
        self, interface: WebhookApprovalInterface, sample_request: ApprovalRequest
    ) -> None:
        """Test building the webhook payload."""
        payload = interface._build_payload(sample_request)

        assert payload["action_id"] == "test-action-123"
        assert payload["agent_id"] == "test-agent"
        assert payload["function_name"] == "transfer_funds"
        assert payload["rule_id"] == "financial_limit"
        assert payload["parameters"]["amount"] == 500.0
        assert payload["reason"] == "Transfer above $100 requires approval"
        assert "timestamp" in payload
        assert "timeout_at" in payload

    def test_build_headers(self, interface: WebhookApprovalInterface) -> None:
        """Test building request headers."""
        headers = interface._build_headers("action-123")

        assert headers["Content-Type"] == "application/json"
        assert headers["X-Sentinel-Token"] == TOKEN
        assert headers["X-Sentinel-Action-ID"] == "action-123"


class TestWebhookSending:
    """Tests for sending the initial webhook."""

    async def test_send_webhook_success(
        self,
        interface: WebhookApprovalInterface,
        sample_request: ApprovalRequest,
        httpx_mock,
    ) -> None:
        """Test successful webhook sending."""
        httpx_mock.add_response(
            method="POST",
            url=WEBHOOK_URL,
            json=create_webhook_response(),
            status_code=202,
        )

        result = await interface._send_webhook(sample_request)
        assert result is True

    async def test_send_webhook_retry_on_failure(
        self,
        interface: WebhookApprovalInterface,
        sample_request: ApprovalRequest,
        httpx_mock,
    ) -> None:
        """Test webhook retry on failure."""
        # First two fail, third succeeds
        httpx_mock.add_response(method="POST", url=WEBHOOK_URL, status_code=500)
        httpx_mock.add_response(method="POST", url=WEBHOOK_URL, status_code=500)
        httpx_mock.add_response(
            method="POST",
            url=WEBHOOK_URL,
            json=create_webhook_response(),
            status_code=202,
        )

        result = await interface._send_webhook(sample_request)
        assert result is True

    async def test_send_webhook_all_retries_fail(
        self,
        interface: WebhookApprovalInterface,
        sample_request: ApprovalRequest,
        httpx_mock,
    ) -> None:
        """Test webhook when all retries fail."""
        # All three attempts fail
        for _ in range(3):
            httpx_mock.add_response(method="POST", url=WEBHOOK_URL, status_code=500)

        result = await interface._send_webhook(sample_request)
        assert result is False

    async def test_send_webhook_network_error(
        self,
        interface: WebhookApprovalInterface,
        sample_request: ApprovalRequest,
        httpx_mock,
    ) -> None:
        """Test webhook with network error."""
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))
        httpx_mock.add_exception(httpx.ConnectError("Connection refused"))

        result = await interface._send_webhook(sample_request)
        assert result is False


class TestStatusPolling:
    """Tests for polling the status endpoint."""

    async def test_poll_approved(
        self, interface: WebhookApprovalInterface, httpx_mock
    ) -> None:
        """Test polling returns approved status."""
        status_url = STATUS_URL_TEMPLATE.format(action_id="test-123")
        httpx_mock.add_response(
            method="GET",
            url=status_url,
            json=create_status_response("test-123", "approved", "admin@example.com"),
        )

        result = await interface._poll_status("test-123")

        assert result.status == ApprovalStatus.APPROVED
        assert result.action_id == "test-123"
        assert result.approved_by == "admin@example.com"

    async def test_poll_denied(
        self, interface: WebhookApprovalInterface, httpx_mock
    ) -> None:
        """Test polling returns denied status."""
        status_url = STATUS_URL_TEMPLATE.format(action_id="test-123")
        httpx_mock.add_response(
            method="GET",
            url=status_url,
            json=create_status_response(
                "test-123", "denied", "admin@example.com", "Amount too high"
            ),
        )

        result = await interface._poll_status("test-123")

        assert result.status == ApprovalStatus.DENIED
        assert result.action_id == "test-123"
        assert result.reason == "Amount too high"

    async def test_poll_pending_then_approved(
        self, interface: WebhookApprovalInterface, httpx_mock
    ) -> None:
        """Test polling with pending then approved."""
        status_url = STATUS_URL_TEMPLATE.format(action_id="test-123")

        # First poll returns pending
        httpx_mock.add_response(
            method="GET",
            url=status_url,
            json=create_status_response("test-123", "pending"),
        )
        # Second poll returns approved
        httpx_mock.add_response(
            method="GET",
            url=status_url,
            json=create_status_response("test-123", "approved", "user@example.com"),
        )

        result = await interface._poll_status("test-123")

        assert result.status == ApprovalStatus.APPROVED

    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_poll_timeout(
        self, interface: WebhookApprovalInterface, httpx_mock
    ) -> None:
        """Test polling times out."""
        status_url = STATUS_URL_TEMPLATE.format(action_id="test-123")

        # With 5s timeout and 0.1s poll interval, we need many responses
        # Use callback for unlimited responses and mark test to allow unmocked requests
        httpx_mock.add_callback(
            lambda request: httpx.Response(
                200, json=create_status_response("test-123", "pending")
            ),
            method="GET",
            url=status_url,
        )

        result = await interface._poll_status("test-123")

        assert result.status == ApprovalStatus.TIMEOUT
        assert result.action_id == "test-123"

    async def test_poll_non_json_response_continues_polling(
        self, interface: WebhookApprovalInterface, httpx_mock
    ) -> None:
        """Test polling continues when server returns non-JSON response."""
        status_url = STATUS_URL_TEMPLATE.format(action_id="test-123")

        # First poll returns HTML (non-JSON)
        httpx_mock.add_response(
            method="GET",
            url=status_url,
            content=b"<html><body>Not Found</body></html>",
            headers={"content-type": "text/html"},
        )
        # Second poll returns valid JSON with approved
        httpx_mock.add_response(
            method="GET",
            url=status_url,
            json=create_status_response("test-123", "approved", "admin@example.com"),
        )

        result = await interface._poll_status("test-123")

        assert result.status == ApprovalStatus.APPROVED
        assert result.action_id == "test-123"
        assert result.approved_by == "admin@example.com"


class TestFullApprovalFlow:
    """Tests for the complete approval flow."""

    async def test_full_flow_approved(
        self,
        interface: WebhookApprovalInterface,
        sample_request: ApprovalRequest,
        httpx_mock,
    ) -> None:
        """Test complete flow with approval."""
        status_url = STATUS_URL_TEMPLATE.format(action_id="test-action-123")

        # Webhook POST succeeds
        httpx_mock.add_response(
            method="POST",
            url=WEBHOOK_URL,
            json=create_webhook_response(),
            status_code=202,
        )
        # Status poll returns approved
        httpx_mock.add_response(
            method="GET",
            url=status_url,
            json=create_status_response("test-action-123", "approved", "approver@test.com"),
        )

        result = await interface.request_approval(sample_request)

        assert result.status == ApprovalStatus.APPROVED
        assert result.action_id == "test-action-123"
        assert result.approved_by == "approver@test.com"

    async def test_full_flow_denied(
        self,
        interface: WebhookApprovalInterface,
        sample_request: ApprovalRequest,
        httpx_mock,
    ) -> None:
        """Test complete flow with denial."""
        status_url = STATUS_URL_TEMPLATE.format(action_id="test-action-123")

        # Webhook POST succeeds
        httpx_mock.add_response(
            method="POST",
            url=WEBHOOK_URL,
            json=create_webhook_response(),
            status_code=202,
        )
        # Status poll returns denied
        httpx_mock.add_response(
            method="GET",
            url=status_url,
            json=create_status_response(
                "test-action-123", "denied", "admin@test.com", "Not authorized"
            ),
        )

        result = await interface.request_approval(sample_request)

        assert result.status == ApprovalStatus.DENIED
        assert result.reason == "Not authorized"

    async def test_full_flow_webhook_fails(
        self,
        interface: WebhookApprovalInterface,
        sample_request: ApprovalRequest,
        httpx_mock,
    ) -> None:
        """Test flow when webhook fails completely."""
        # All webhook attempts fail
        for _ in range(3):
            httpx_mock.add_response(method="POST", url=WEBHOOK_URL, status_code=500)

        result = await interface.request_approval(sample_request)

        assert result.status == ApprovalStatus.ERROR
        assert "Failed to send webhook" in (result.reason or "")

    @pytest.mark.httpx_mock(assert_all_requests_were_expected=False)
    async def test_full_flow_timeout(
        self,
        interface: WebhookApprovalInterface,
        sample_request: ApprovalRequest,
        httpx_mock,
    ) -> None:
        """Test complete flow with timeout."""
        status_url = STATUS_URL_TEMPLATE.format(action_id="test-action-123")

        # Webhook POST succeeds
        httpx_mock.add_response(
            method="POST",
            url=WEBHOOK_URL,
            json=create_webhook_response(),
            status_code=202,
        )
        # Status always pending - use callback for unlimited responses
        httpx_mock.add_callback(
            lambda request: httpx.Response(
                200, json=create_status_response("test-action-123", "pending")
            ),
            method="GET",
            url=status_url,
        )

        result = await interface.request_approval(sample_request)

        assert result.status == ApprovalStatus.TIMEOUT


class TestFormatRequest:
    """Tests for request formatting."""

    def test_format_request(
        self, interface: WebhookApprovalInterface, sample_request: ApprovalRequest
    ) -> None:
        """Test formatting the request for logging."""
        formatted = interface.format_request(sample_request)

        assert "test-action-123" in formatted
        assert "test-agent" in formatted
        assert "transfer_funds" in formatted
        assert "financial_limit" in formatted


class TestMockApprovalState:
    """Tests for the MockApprovalState helper."""

    def test_receive_and_approve(self) -> None:
        """Test receiving and approving a request."""
        state = MockApprovalState()

        state.receive_request("action-1", {"function": "test"})
        assert state.get_status("action-1")["status"] == "pending"

        state.approve("action-1", "admin@test.com")
        status = state.get_status("action-1")
        assert status["status"] == "approved"
        assert status["approved_by"] == "admin@test.com"

    def test_receive_and_deny(self) -> None:
        """Test receiving and denying a request."""
        state = MockApprovalState()

        state.receive_request("action-2", {"function": "test"})
        state.deny("action-2", "Too expensive", "manager@test.com")

        status = state.get_status("action-2")
        assert status["status"] == "denied"
        assert status["reason"] == "Too expensive"
        assert status["approved_by"] == "manager@test.com"

    def test_reset(self) -> None:
        """Test resetting state."""
        state = MockApprovalState()
        state.receive_request("action-1", {"function": "test"})
        state.approve("action-1")

        state.reset()

        assert len(state.requests) == 0
        assert len(state.responses) == 0
