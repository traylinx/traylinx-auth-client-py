"""
Tests for RPC and A2A functionality in TraylinxAuthClient.
"""

import pytest
from unittest.mock import patch, Mock, MagicMock
from traylinx_auth_client.client import TraylinxAuthClient
from traylinx_auth_client.main import (
    get_a2a_request_headers,
    validate_dual_auth_request,
    require_dual_auth,
    a2a_request,
    make_a2a_request,
)
from traylinx_auth_client.exceptions import AuthenticationError, NetworkError, TraylinxAuthError
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient


# Test RPC Methods
class TestRPCMethods:
    """Test JSON-RPC methods in TraylinxAuthClient."""

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_rpc_call_to_auth_service(self, mock_create_session, mock_fetch):
        """Test RPC call to auth service (uses access token)."""
        # Mock session
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"jsonrpc": "2.0", "result": {"status": "ok"}, "id": "123"}
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        
        # Set tokens manually
        client._access_token = "test_access_token"
        client._agent_secret_token = "test_secret_token"
        client._token_expiration = 9999999999  # Far in the future

        result = client.rpc_call("health_check", {})

        # RPC methods return the full JSON-RPC response
        assert result["result"] == {"status": "ok"}
        assert result["jsonrpc"] == "2.0"

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_rpc_introspect_token(self, mock_create_session, mock_fetch):
        """Test rpc_introspect_token method."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "result": {"active": True, "agent_id": "test_agent"},
            "id": "789",
        }
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        
        client._access_token = "test_access_token"
        client._agent_secret_token = "test_secret_token"
        client._token_expiration = 9999999999

        result = client.rpc_introspect_token("token123", "agent456")

        # RPC methods return the full JSON-RPC response
        assert result["result"] == {"active": True, "agent_id": "test_agent"}
        assert result["jsonrpc"] == "2.0"

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_rpc_get_capabilities(self, mock_create_session, mock_fetch):
        """Test rpc_get_capabilities method."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "result": {"capabilities": ["read", "write"]},
            "id": "abc",
        }
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        
        client._access_token = "test_access_token"
        client._agent_secret_token = "test_secret_token"
        client._token_expiration = 9999999999

        result = client.rpc_get_capabilities()

        # RPC methods return the full JSON-RPC response
        assert result["result"] == {"capabilities": ["read", "write"]}
        assert result["jsonrpc"] == "2.0"

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_rpc_health_check(self, mock_create_session, mock_fetch):
        """Test rpc_health_check method."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"jsonrpc": "2.0", "result": {"status": "healthy"}, "id": "def"}
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        
        client._access_token = "test_access_token"
        client._agent_secret_token = "test_secret_token"
        client._token_expiration = 9999999999

        result = client.rpc_health_check()

        # RPC methods return the full JSON-RPC response
        assert result["result"] == {"status": "healthy"}
        assert result["jsonrpc"] == "2.0"

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_rpc_call_with_agent_credentials(self, mock_create_session, mock_fetch):
        """Test RPC call with explicit agent credentials."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"jsonrpc": "2.0", "result": {"data": "test"}, "id": "xyz"}
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        
        client._access_token = "test_access_token"
        client._agent_secret_token = "test_secret_token"
        client._token_expiration = 9999999999

        result = client.rpc_call(
            "get_data",
            {"param": "value"},
            rpc_url="https://other-agent.com/rpc",
            include_agent_credentials=True
        )

        assert result["result"] == {"data": "test"}
        # Verify agent credentials were used
        call_args = mock_session.post.call_args
        assert "X-Agent-Secret-Token" in call_args[1]["headers"]

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_rpc_call_invalid_request_error(self, mock_create_session, mock_fetch):
        """Test RPC call with JSON-RPC invalid request error."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "Invalid Request"},
            "id": "xyz"
        }
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        
        client._access_token = "test_access_token"
        client._agent_secret_token = "test_secret_token"
        client._token_expiration = 9999999999

        from traylinx_auth_client.exceptions import ValidationError
        with pytest.raises(ValidationError, match="Invalid RPC request"):
            client.rpc_call("test_method", {})

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_rpc_call_method_not_found_error(self, mock_create_session, mock_fetch):
        """Test RPC call with method not found error."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32601, "message": "Method not found"},
            "id": "xyz"
        }
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        
        client._access_token = "test_access_token"
        client._agent_secret_token = "test_secret_token"
        client._token_expiration = 9999999999

        from traylinx_auth_client.exceptions import ValidationError
        with pytest.raises(ValidationError, match="Method not found"):
            client.rpc_call("unknown_method", {})

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_rpc_call_invalid_params_error(self, mock_create_session, mock_fetch):
        """Test RPC call with invalid params error."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32602, "message": "Invalid params"},
            "id": "xyz"
        }
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        
        client._access_token = "test_access_token"
        client._agent_secret_token = "test_secret_token"
        client._token_expiration = 9999999999

        from traylinx_auth_client.exceptions import ValidationError
        with pytest.raises(ValidationError, match="Invalid RPC parameters"):
            client.rpc_call("test_method", {"bad": "params"})

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_rpc_call_generic_error(self, mock_create_session, mock_fetch):
        """Test RPC call with generic RPC error."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "error": {"code": -32000, "message": "Server error"},
            "id": "xyz"
        }
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        
        client._access_token = "test_access_token"
        client._agent_secret_token = "test_secret_token"
        client._token_expiration = 9999999999

        with pytest.raises(TraylinxAuthError, match="RPC error"):
            client.rpc_call("test_method", {})


# Test A2A Methods
class TestA2AMethods:
    """Test A2A-specific methods in TraylinxAuthClient."""

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_get_a2a_headers(self, mock_create_session, mock_fetch):
        """Test get_a2a_headers returns Bearer token format."""
        mock_session = Mock()
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        
        client._access_token = "test_access_token"
        client._agent_secret_token = "test_secret_token"
        client._token_expiration = 9999999999

        headers = client.get_a2a_headers()

        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer test_secret_token"
        assert "X-Agent-User-Id" in headers
        assert headers["X-Agent-User-Id"] == "12345678-1234-1234-1234-123456789abc"

    @patch("traylinx_auth_client.client.TraylinxAuthClient.validate_token")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_validate_a2a_request_bearer_format(self, mock_create_session, mock_fetch, mock_validate):
        """Test validate_a2a_request with Bearer token format."""
        mock_session = Mock()
        mock_create_session.return_value = mock_session
        mock_validate.return_value = True

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        headers = {
            "Authorization": "Bearer test_token",
            "X-Agent-User-Id": "agent123",
        }

        result = client.validate_a2a_request(headers)

        assert result is True
        mock_validate.assert_called_once_with("test_token", "agent123")

    @patch("traylinx_auth_client.client.TraylinxAuthClient.validate_token")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_validate_a2a_request_custom_format(self, mock_create_session, mock_fetch, mock_validate):
        """Test validate_a2a_request with custom header format."""
        mock_session = Mock()
        mock_create_session.return_value = mock_session
        mock_validate.return_value = True

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        headers = {
            "X-Agent-Secret-Token": "test_token",
            "X-Agent-User-Id": "agent123",
        }

        result = client.validate_a2a_request(headers)

        assert result is True
        mock_validate.assert_called_once_with("test_token", "agent123")

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_detect_auth_mode_bearer(self, mock_create_session, mock_fetch):
        """Test detect_auth_mode with Bearer token."""
        mock_session = Mock()
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        headers = {
            "Authorization": "Bearer test_token",
            "X-Agent-User-Id": "agent123",
        }

        mode = client.detect_auth_mode(headers)

        assert mode == "bearer"

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_detect_auth_mode_custom(self, mock_create_session, mock_fetch):
        """Test detect_auth_mode with custom headers."""
        mock_session = Mock()
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        headers = {
            "X-Agent-Secret-Token": "test_token",
            "X-Agent-User-Id": "agent123",
        }

        mode = client.detect_auth_mode(headers)

        assert mode == "custom"

    @patch("traylinx_auth_client.client.TraylinxAuthClient._fetch_tokens")
    @patch("traylinx_auth_client.client.TraylinxAuthClient._create_session_with_retries")
    def test_detect_auth_mode_none(self, mock_create_session, mock_fetch):
        """Test detect_auth_mode with no auth headers."""
        mock_session = Mock()
        mock_create_session.return_value = mock_session

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        headers = {"Content-Type": "application/json"}

        mode = client.detect_auth_mode(headers)

        assert mode == "none"


# Test Utility Functions
class TestA2AUtilityFunctions:
    """Test A2A utility functions in main.py."""

    @patch("traylinx_auth_client.main.get_default_client")
    def test_get_a2a_request_headers(self, mock_get_client):
        """Test get_a2a_request_headers function."""
        mock_client = Mock()
        mock_client.get_a2a_headers.return_value = {
            "Authorization": "Bearer test_token",
            "X-Agent-User-Id": "test_agent",
        }
        mock_get_client.return_value = mock_client

        headers = get_a2a_request_headers()

        assert headers["Authorization"] == "Bearer test_token"
        assert headers["X-Agent-User-Id"] == "test_agent"

    @patch("traylinx_auth_client.main.get_default_client")
    def test_validate_dual_auth_request_bearer(self, mock_get_client):
        """Test validate_dual_auth_request with Bearer token."""
        mock_client = Mock()
        mock_client.validate_a2a_request.return_value = True
        mock_get_client.return_value = mock_client

        headers = {
            "Authorization": "Bearer test_token",
            "X-Agent-User-Id": "agent123",
        }

        result = validate_dual_auth_request(headers)

        assert result is True
        mock_client.validate_a2a_request.assert_called_once_with(headers)


# Test Decorators
class TestA2ADecorators:
    """Test A2A decorators."""

    def test_require_dual_auth_success(self):
        """Test @require_dual_auth decorator with valid auth."""
        app = FastAPI()

        @app.get("/test")
        @require_dual_auth
        async def test_endpoint(request: Request):
            return {"message": "success"}

        client = TestClient(app)

        with patch("traylinx_auth_client.main.validate_dual_auth_request") as mock_validate:
            mock_validate.return_value = True

            headers = {
                "Authorization": "Bearer test_token",
                "X-Agent-User-Id": "agent123",
            }

            response = client.get("/test", headers=headers)

            assert response.status_code == 200
            assert response.json() == {"message": "success"}

    def test_require_dual_auth_failure(self):
        """Test @require_dual_auth decorator with invalid auth."""
        app = FastAPI()

        @app.get("/test")
        @require_dual_auth
        async def test_endpoint(request: Request):
            return {"message": "success"}

        client = TestClient(app)

        with patch("traylinx_auth_client.main.validate_dual_auth_request") as mock_validate:
            mock_validate.return_value = False

            headers = {
                "Authorization": "Bearer invalid_token",
                "X-Agent-User-Id": "agent123",
            }

            response = client.get("/test", headers=headers)

            assert response.status_code == 401
            assert "Invalid or missing authentication" in response.json()["detail"]

    @patch("traylinx_auth_client.main.get_agent_request_headers")
    @patch("requests.request")
    def test_a2a_request_decorator(self, mock_request, mock_get_headers):
        """Test @a2a_request decorator."""
        mock_get_headers.return_value = {
            "X-Agent-Secret-Token": "test_token",
            "X-Agent-User-Id": "test_agent",
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "success"}
        mock_response.raise_for_status = Mock()
        mock_request.return_value = mock_response

        @a2a_request("GET", "https://other-agent.com/api/data")
        def fetch_data():
            """Test function."""
            return None

        result = fetch_data()

        assert result == {"result": "success"}
        mock_request.assert_called_once()

    @patch("traylinx_auth_client.main.get_agent_request_headers")
    @patch("requests.request")
    def test_a2a_request_decorator_with_headers(self, mock_request, mock_get_headers):
        """Test @a2a_request decorator with additional headers."""
        mock_get_headers.return_value = {
            "X-Agent-Secret-Token": "test_token",
            "X-Agent-User-Id": "test_agent",
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"result": "success"}
        mock_response.raise_for_status = Mock()
        mock_request.return_value = mock_response

        @a2a_request("POST", "https://other-agent.com/api/data", headers={"Custom-Header": "value"})
        def post_data():
            """Test function."""
            return None

        result = post_data()

        assert result == {"result": "success"}
        # Verify headers were merged
        call_args = mock_request.call_args
        headers = call_args[1]["headers"]
        assert "Custom-Header" in headers
        assert "X-Agent-Secret-Token" in headers

    @patch("traylinx_auth_client.main.get_agent_request_headers")
    @patch("requests.request")
    def test_make_a2a_request(self, mock_request, mock_get_headers):
        """Test make_a2a_request function."""
        mock_get_headers.return_value = {
            "X-Agent-Secret-Token": "test_token",
            "X-Agent-User-Id": "test_agent",
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_response.raise_for_status = Mock()
        mock_request.return_value = mock_response

        result = make_a2a_request("GET", "https://other-agent.com/api/data")

        assert result == {"data": "test"}
        mock_request.assert_called_once()

    @patch("traylinx_auth_client.main.get_agent_request_headers")
    @patch("requests.request")
    def test_make_a2a_request_with_headers(self, mock_request, mock_get_headers):
        """Test make_a2a_request with additional headers."""
        mock_get_headers.return_value = {
            "X-Agent-Secret-Token": "test_token",
            "X-Agent-User-Id": "test_agent",
        }

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_response.raise_for_status = Mock()
        mock_request.return_value = mock_response

        result = make_a2a_request(
            "POST",
            "https://other-agent.com/api/data",
            headers={"Custom-Header": "value"},
            json={"test": "data"}
        )

        assert result == {"data": "test"}
        # Verify headers were merged
        call_args = mock_request.call_args
        headers = call_args[1]["headers"]
        assert "Custom-Header" in headers
        assert "X-Agent-Secret-Token" in headers
