"""
Simple tests for the TraylinxAuthClient class to improve coverage.
"""

import pytest
from unittest.mock import Mock
from traylinx_auth_client.client import TraylinxAuthClient
from traylinx_auth_client.exceptions import AuthenticationError, NetworkError


class TestClientBasics:
    """Test basic client functionality."""

    def test_client_initialization(self):
        """Test basic client initialization."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        assert client.client_id == "test_client"
        assert client.client_secret == "test_secret_123"
        assert client.api_base_url == "https://api.example.com/"
        assert client.agent_user_id == "12345678-1234-1234-1234-123456789abc"

    def test_token_fetch_success(self):
        """Test successful token fetching."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "agent_secret_token": "test_agent_secret_token",
            "expires_in": 3600,
        }
        mock_response.raise_for_status.return_value = None

        # Replace session with mock
        mock_session = Mock()
        mock_session.post.return_value = mock_response
        client._session = mock_session

        # Test token retrieval
        access_token = client.get_access_token()
        agent_secret_token = client.get_agent_secret_token()

        assert access_token == "test_access_token"
        assert agent_secret_token == "test_agent_secret_token"

    def test_header_generation(self):
        """Test header generation."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "header_access_token",
            "agent_secret_token": "header_agent_token",
            "expires_in": 3600,
        }
        mock_response.raise_for_status.return_value = None

        mock_session = Mock()
        mock_session.post.return_value = mock_response
        client._session = mock_session

        # Test auth service headers
        auth_headers = client.get_request_headers()
        expected_auth = {
            "Authorization": "Bearer header_access_token",
            "X-Agent-Secret-Token": "header_agent_token",
            "X-Agent-User-Id": "12345678-1234-1234-1234-123456789abc",
        }
        assert auth_headers == expected_auth

        # Test agent-to-agent headers
        agent_headers = client.get_agent_request_headers()
        expected_agent = {
            "X-Agent-Secret-Token": "header_agent_token",
            "X-Agent-User-Id": "12345678-1234-1234-1234-123456789abc",
        }
        assert agent_headers == expected_agent
        assert "Authorization" not in agent_headers

        # Test A2A headers
        a2a_headers = client.get_a2a_headers()
        expected_a2a = {
            "Authorization": "Bearer header_agent_token",
            "X-Agent-User-Id": "12345678-1234-1234-1234-123456789abc",
        }
        assert a2a_headers == expected_a2a

    def test_auth_mode_detection(self):
        """Test authentication mode detection."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        # Test Bearer token detection
        bearer_headers = {"Authorization": "Bearer test_token"}
        assert client.detect_auth_mode(bearer_headers) == "bearer"

        # Test custom header detection
        custom_headers = {"X-Agent-Secret-Token": "test_token"}
        assert client.detect_auth_mode(custom_headers) == "custom"

        # Test no auth detection
        no_auth_headers = {"Content-Type": "application/json"}
        assert client.detect_auth_mode(no_auth_headers) == "none"

    def test_malformed_token_response(self):
        """Test handling of malformed token responses."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        # Mock response missing required fields
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_token"
            # Missing agent_secret_token and expires_in
        }
        mock_response.raise_for_status.return_value = None

        mock_session = Mock()
        mock_session.post.return_value = mock_response
        client._session = mock_session

        with pytest.raises(AuthenticationError, match="missing fields"):
            client.get_access_token()

    def test_context_manager(self):
        """Test client as context manager."""
        with TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        ) as client:
            assert client.client_id == "test_client"

        # Verify close method exists
        assert hasattr(client, "close")
