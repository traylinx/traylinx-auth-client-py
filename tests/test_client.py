"""
Comprehensive tests for the TraylinxAuthClient class.

This module tests the core client functionality, including initialization,
token management, API calls, and error handling.
"""

import pytest
import time
from unittest.mock import Mock, MagicMock, patch
from requests.exceptions import HTTPError, ConnectionError, Timeout
import requests

from traylinx_auth_client.client import TraylinxAuthClient
from traylinx_auth_client.exceptions import (
    TraylinxAuthError,
    AuthenticationError,
    ValidationError,
    NetworkError,
    TokenExpiredError,
)


class TestTraylinxAuthClientInitialization:
    """Test client initialization and configuration."""

    def test_valid_initialization_with_parameters(self):
        """Test successful client initialization with all parameters."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
            timeout=60,
            max_retries=5,
            retry_delay=2.0,
            cache_tokens=False,
            log_level="DEBUG",
        )

        assert client.config.client_id == "test_client"
        assert client.config.client_secret == "test_secret_123"
        assert str(client.config.api_base_url) == "https://api.example.com/"
        assert client.config.agent_user_id == "12345678-1234-1234-1234-123456789abc"
        assert client.config.timeout == 60
        assert client.config.max_retries == 5
        assert client.config.retry_delay == 2.0
        assert client.config.cache_tokens is False
        assert client.config.log_level == "DEBUG"

    def test_initialization_with_environment_variables(self):
        """Test client initialization using environment variables."""
        with patch.dict(
            "os.environ",
            {
                "TRAYLINX_CLIENT_ID": "env_client",
                "TRAYLINX_CLIENT_SECRET": "env_secret_123",
                "TRAYLINX_API_BASE_URL": "https://env.example.com/",
                "TRAYLINX_AGENT_USER_ID": "abcdef12-3456-7890-abcd-ef1234567890",
            },
        ):
            client = TraylinxAuthClient()

        assert client.config.client_id == "env_client"
        assert client.config.client_secret == "env_secret_123"
        assert str(client.config.api_base_url) == "https://env.example.com/"
        assert client.config.agent_user_id == "abcdef12-3456-7890-abcd-ef1234567890"

    def test_initialization_validation_raises_ValidationError(self):
        """Test that initialization with invalid parameters raises ValidationError."""
        # Test invalid client_id
        with pytest.raises(ValidationError, match="client_id"):
            TraylinxAuthClient(
                client_id="",  # Empty
                client_secret="test_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        # Test invalid client_secret
        with pytest.raises(ValidationError, match="client_secret"):
            TraylinxAuthClient(
                client_id="test_client",
                client_secret="short",  # Too short
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        # Test invalid URL
        with pytest.raises(ValidationError, match="api_base_url"):
            TraylinxAuthClient(
                client_id="test_client",
                client_secret="test_secret_123",
                api_base_url="http://insecure.com",  # HTTP not allowed
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        # Test invalid UUID
        with pytest.raises(ValidationError, match="agent_user_id"):
            TraylinxAuthClient(
                client_id="test_client",
                client_secret="test_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="not-a-uuid",
            )


class TestTokenManagement:
    """Test token fetching and management."""

    def test_successful_token_fetch(self):
        """Test that tokens are fetched successfully."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        # Mock the session after client creation
        mock_session = Mock()
        client._session = mock_session

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "access_token": "test_access_token",
            "agent_secret_token": "test_agent_secret_token",
            "expires_in": 3600,
        }
        mock_session.post.return_value = mock_response

        # Test token retrieval
        access_token = client.get_access_token()
        agent_secret_token = client.get_agent_secret_token()

        assert access_token == "test_access_token"
        assert agent_secret_token == "test_agent_secret_token"

        # Verify the request was made correctly
        call_args = mock_session.post.call_args
        assert call_args[0][0] == "https://api.example.com/oauth/token"
        assert call_args[1]["data"]["grant_type"] == "client_credentials"
        assert call_args[1]["data"]["client_id"] == "test_client"
        assert call_args[1]["data"]["client_secret"] == "test_secret_123"
        assert call_args[1]["data"]["scope"] == "a2a"

    def test_token_caching_when_not_expired(self):
        """Test that tokens are cached and not refetched unnecessarily."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        mock_session = Mock()
        client._session = mock_session

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "access_token": "cached_access_token",
            "agent_secret_token": "cached_agent_secret_token",
            "expires_in": 3600,
        }
        mock_session.post.return_value = mock_response

        # First call should fetch tokens
        token1 = client.get_access_token()
        assert mock_session.post.call_count == 1
        assert token1 == "cached_access_token"

        # Second call should use cached tokens
        token2 = client.get_access_token()
        assert mock_session.post.call_count == 1  # No additional calls
        assert token2 == "cached_access_token"

        # Third call for agent secret token should also use cache
        agent_token = client.get_agent_secret_token()
        assert mock_session.post.call_count == 1  # Still no additional calls
        assert agent_token == "cached_agent_secret_token"


class TestRequestHeaders:
    """Test request header generation for different use cases."""

    def test_get_request_headers_for_auth_service(self):
        """Test headers for calling auth service (includes access_token)."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        mock_session = Mock()
        client._session = mock_session

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "access_token": "auth_service_token",
            "agent_secret_token": "agent_service_token",
            "expires_in": 3600,
        }
        mock_session.post.return_value = mock_response

        headers = client.get_request_headers()
        expected_headers = {
            "Authorization": "Bearer auth_service_token",
            "X-Agent-Secret-Token": "agent_service_token",
            "X-Agent-User-Id": "12345678-1234-1234-1234-123456789abc",
        }

        assert headers == expected_headers

    def test_get_agent_request_headers_for_calling_others(self):
        """Test headers for calling other agents (ONLY agent_secret_token)."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        mock_session = Mock()
        client._session = mock_session

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "access_token": "auth_service_token",
            "agent_secret_token": "agent_service_token",
            "expires_in": 3600,
        }
        mock_session.post.return_value = mock_response

        headers = client.get_agent_request_headers()
        expected_headers = {
            "X-Agent-Secret-Token": "agent_service_token",
            "X-Agent-User-Id": "12345678-1234-1234-1234-123456789abc",
        }

        assert headers == expected_headers
        # Should NOT include Authorization header for agent-to-agent calls
        assert "Authorization" not in headers


class TestErrorHandling:
    """Test comprehensive error handling scenarios."""

    def test_http_error_401(self):
        """Test handling of 401 HTTP errors."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        mock_session = Mock()
        client._session = mock_session

        # Mock HTTP error
        http_error = HTTPError("401 Unauthorized")
        mock_response = Mock()
        mock_response.status_code = 401
        http_error.response = mock_response
        mock_session.post.side_effect = http_error

        with pytest.raises(AuthenticationError, match="Authentication failed"):
            client.get_access_token()

    def test_http_error_429(self):
        """Test handling of 429 rate limit errors."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        mock_session = Mock()
        client._session = mock_session

        # Mock HTTP error
        http_error = HTTPError("429 Too Many Requests")
        mock_response = Mock()
        mock_response.status_code = 429
        http_error.response = mock_response
        mock_session.post.side_effect = http_error

        with pytest.raises(NetworkError, match="Rate limit exceeded"):
            client.get_access_token()

    def test_http_error_500(self):
        """Test handling of 500 server errors."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        mock_session = Mock()
        client._session = mock_session

        # Mock HTTP error
        http_error = HTTPError("500 Internal Server Error")
        mock_response = Mock()
        mock_response.status_code = 500
        http_error.response = mock_response
        mock_session.post.side_effect = http_error

        with pytest.raises(NetworkError, match="Server error"):
            client.get_access_token()

    def test_connection_error(self):
        """Test handling of connection errors."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        mock_session = Mock()
        client._session = mock_session

        # Mock connection error
        connection_error = ConnectionError("Connection failed")
        mock_session.post.side_effect = connection_error

        with pytest.raises(NetworkError, match="Connection failed"):
            client.get_access_token()

    def test_network_timeout_error(self):
        """Test handling of network timeout errors."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        mock_session = Mock()
        client._session = mock_session

        # Mock timeout error
        timeout_error = Timeout("Request timeout")
        mock_session.post.side_effect = timeout_error

        with pytest.raises(NetworkError, match="Request timeout"):
            client.get_access_token()

    def test_malformed_token_response(self):
        """Test handling of malformed token responses."""
        client = TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        mock_session = Mock()
        client._session = mock_session

        # Mock response with missing required fields
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "access_token": "test_token"
            # Missing agent_secret_token and expires_in
        }
        mock_session.post.return_value = mock_response

        with pytest.raises(AuthenticationError, match="missing fields"):
            client.get_access_token()


class TestContextManager:
    """Test client as context manager."""

    def test_context_manager_usage(self):
        """Test client can be used as context manager."""
        with TraylinxAuthClient(
            client_id="test_client",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        ) as client:
            assert client.config.client_id == "test_client"
            # Session should be closed after context, but we can't test
            # this directly, but we can verify the close method exists
            assert hasattr(client, "close")
