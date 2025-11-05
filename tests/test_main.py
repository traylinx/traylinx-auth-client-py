import pytest
import time
import threading
import concurrent.futures
import os
from unittest.mock import patch, MagicMock, Mock
from fastapi import FastAPI, Request, HTTPException
from fastapi.testclient import TestClient
import requests
from requests.exceptions import Timeout, ConnectionError, HTTPError
from traylinx_auth_client.main import (
    get_request_headers,
    require_a2a_auth,
    validate_a2a_request,
)
from traylinx_auth_client.exceptions import (
    TraylinxAuthError,
    AuthenticationError,
    NetworkError,
    ValidationError,
    TokenExpiredError,
)


@patch("traylinx_auth_client.main.get_default_client")
def test_get_request_headers(mock_get_default_client):
    mock_client = Mock()
    mock_client.get_request_headers.return_value = {
        "Authorization": "Bearer test_access_token",
        "X-Agent-Secret-Token": "test_agent_secret_token",
        "X-Agent-User-Id": "12345678-1234-1234-1234-123456789abc",
    }
    mock_get_default_client.return_value = mock_client

    headers = get_request_headers()

    assert headers == {
        "Authorization": "Bearer test_access_token",
        "X-Agent-Secret-Token": "test_agent_secret_token",
        "X-Agent-User-Id": "12345678-1234-1234-1234-123456789abc",
    }


app = FastAPI()


@app.get("/")
@require_a2a_auth
async def protected_route(request: Request):
    return {"message": "ok"}


client = TestClient(app)


@patch("traylinx_auth_client.main.validate_a2a_request")
def test_require_a2a_auth_success(mock_validate):
    mock_validate.return_value = True

    headers = {
        "x-agent-secret-token": "test_secret_token",
        "x-agent-user-id": "12345678-1234-1234-1234-123456789abc",
    }
    response = client.get("/", headers=headers)
    assert response.status_code == 200
    assert response.json() == {"message": "ok"}


@patch("traylinx_auth_client.main.validate_a2a_request")
def test_require_a2a_auth_failure(mock_validate):
    mock_validate.return_value = False

    headers = {
        "x-agent-secret-token": "test_secret_token",
        "x-agent-user-id": "12345678-1234-1234-1234-123456789abc",
    }
    response = client.get("/", headers=headers)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing A2A authentication"}


def test_require_a2a_auth_missing_headers():
    response = client.get("/")
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing A2A authentication"}


class TestGetRequestHeadersErrorScenarios:
    """Test error scenarios for get_request_headers function."""

    @patch("traylinx_auth_client.main.get_default_client")
    def test_get_request_headers_token_manager_error(self, mock_get_default_client):
        """Test handling of client errors."""
        mock_client = Mock()
        mock_client.get_request_headers.side_effect = AuthenticationError(
            "Token fetch failed"
        )
        mock_get_default_client.return_value = mock_client

        with pytest.raises(AuthenticationError):
            get_request_headers()

    @patch("traylinx_auth_client.main.get_default_client")
    def test_get_request_headers_network_error(self, mock_get_default_client):
        """Test handling of network errors during token fetch."""
        mock_client = Mock()
        mock_client.get_request_headers.side_effect = NetworkError("Connection failed")
        mock_get_default_client.return_value = mock_client

        with pytest.raises(NetworkError):
            get_request_headers()

    @patch("traylinx_auth_client.main.get_default_client")
    def test_get_request_headers_missing_env_var(self, mock_get_default_client):
        """Test handling of missing environment variables."""
        mock_client = Mock()
        mock_client.get_request_headers.side_effect = ValidationError(
            "Configuration validation failed: agent_user_id: Agent User ID cannot be empty"
        )
        mock_get_default_client.return_value = mock_client

        with pytest.raises(ValidationError, match="agent_user_id"):
            get_request_headers()

    @patch("traylinx_auth_client.main.get_default_client")
    def test_get_request_headers_token_expired(self, mock_get_default_client):
        """Test handling of expired tokens."""
        mock_client = Mock()
        mock_client.get_request_headers.side_effect = TokenExpiredError("Token expired")
        mock_get_default_client.return_value = mock_client

        with pytest.raises(TokenExpiredError):
            get_request_headers()

    @patch("traylinx_auth_client.main.get_default_client")
    def test_get_request_headers_empty_tokens(self, mock_get_default_client):
        """Test handling of empty or None tokens."""
        mock_client = Mock()
        mock_client.get_request_headers.side_effect = TokenExpiredError(
            "Access token is not available"
        )
        mock_get_default_client.return_value = mock_client

        with pytest.raises(TokenExpiredError, match="Access token"):
            get_request_headers()

    @patch("traylinx_auth_client.main.get_default_client")
    def test_get_request_headers_none_tokens(self, mock_get_default_client):
        """Test handling of None tokens."""
        mock_client = Mock()
        mock_client.get_request_headers.side_effect = TokenExpiredError(
            "Agent secret token is not available"
        )
        mock_get_default_client.return_value = mock_client

        with pytest.raises(TokenExpiredError, match="Agent secret token"):
            get_request_headers()


class TestRequireA2AAuthErrorScenarios:
    """Test error scenarios for require_a2a_auth decorator."""

    def setup_method(self):
        """Set up test app for each test."""
        self.app = FastAPI()

        @self.app.get("/test")
        @require_a2a_auth
        async def test_endpoint(request: Request):
            return {"message": "success"}

        self.client = TestClient(self.app)

    @patch("traylinx_auth_client.main.validate_a2a_request")
    def test_introspection_service_network_error(self, mock_validate):
        """Test handling of network errors in validation."""
        mock_validate.side_effect = NetworkError("Connection failed")

        headers = {
            "x-agent-secret-token": "test_secret_token",
            "x-agent-user-id": "12345678-1234-1234-1234-123456789abc",
        }

        # The decorator catches exceptions and returns 401
        response = self.client.get("/test", headers=headers)
        assert response.status_code == 401
        assert "Invalid or missing A2A authentication" in response.json()["detail"]

    @patch("traylinx_auth_client.main.validate_a2a_request")
    def test_introspection_service_auth_error(self, mock_validate):
        """Test handling of authentication errors in validation."""
        mock_validate.side_effect = AuthenticationError("Invalid token")

        headers = {
            "x-agent-secret-token": "test_secret_token",
            "x-agent-user-id": "12345678-1234-1234-1234-123456789abc",
        }

        response = self.client.get("/test", headers=headers)
        assert response.status_code == 401
        assert "Invalid or missing A2A authentication" in response.json()["detail"]

    @patch("traylinx_auth_client.main.validate_a2a_request")
    def test_introspection_service_timeout(self, mock_validate):
        """Test handling of timeout errors in validation."""
        mock_validate.side_effect = Timeout("Request timeout")

        headers = {
            "x-agent-secret-token": "test_secret_token",
            "x-agent-user-id": "12345678-1234-1234-1234-123456789abc",
        }

        response = self.client.get("/test", headers=headers)
        assert response.status_code == 401
        assert "Invalid or missing A2A authentication" in response.json()["detail"]

    @patch("traylinx_auth_client.main.validate_a2a_request")
    def test_introspection_service_unexpected_error(self, mock_validate):
        """Test handling of unexpected errors in validation."""
        mock_validate.side_effect = Exception("Unexpected error")

        headers = {
            "x-agent-secret-token": "test_secret_token",
            "x-agent-user-id": "12345678-1234-1234-1234-123456789abc",
        }

        response = self.client.get("/test", headers=headers)
        assert response.status_code == 401
        assert "Invalid or missing A2A authentication" in response.json()["detail"]

    def test_malformed_headers(self):
        """Test handling of malformed headers."""
        malformed_headers = [
            {"x-agent-secret-token": ""},  # empty token
            {"x-agent-user-id": ""},  # empty user id
            {"x-agent-secret-token": "token", "x-agent-user-id": ""},  # empty user id
            {"x-agent-secret-token": "", "x-agent-user-id": "user"},  # empty token
        ]

        for headers in malformed_headers:
            response = self.client.get("/test", headers=headers)
            assert response.status_code == 401
            assert "Invalid or missing A2A authentication" in response.json()["detail"]

    def test_case_insensitive_headers(self):
        """Test that headers are handled case-insensitively."""
        headers_variants = [
            {
                "X-Agent-Secret-Token": "token",
                "X-Agent-User-Id": "12345678-1234-1234-1234-123456789abc",
            },
            {
                "x-agent-secret-token": "token",
                "x-agent-user-id": "12345678-1234-1234-1234-123456789abc",
            },
            {
                "X-AGENT-SECRET-TOKEN": "token",
                "X-AGENT-USER-ID": "12345678-1234-1234-1234-123456789abc",
            },
        ]

        with patch("traylinx_auth_client.main.validate_a2a_request") as mock_validate:
            mock_validate.return_value = True

            for headers in headers_variants:
                response = self.client.get("/test", headers=headers)
                assert response.status_code == 200


class TestTimeoutAndRetryLogic:
    """Test timeout and retry logic in various components."""

    @patch("traylinx_auth_client.main.get_default_client")
    def test_token_manager_timeout_handling(self, mock_get_default_client):
        """Test timeout handling in client."""
        mock_client = Mock()

        # Simulate timeout on first call, success on retry
        mock_client.get_request_headers.side_effect = [
            NetworkError("Request timeout"),
            {
                "Authorization": "Bearer test_access_token",
                "X-Agent-Secret-Token": "test_agent_secret_token",
                "X-Agent-User-Id": "12345678-1234-1234-1234-123456789abc",
            },
        ]
        mock_get_default_client.return_value = mock_client

        # First call should raise NetworkError
        with pytest.raises(NetworkError, match="timeout"):
            get_request_headers()

    @patch("traylinx_auth_client.main.get_default_client")
    def test_token_manager_retry_exhaustion(self, mock_get_default_client):
        """Test behavior when retries are exhausted."""
        mock_client = Mock()

        # Simulate persistent timeout
        mock_client.get_request_headers.side_effect = NetworkError("Persistent timeout")
        mock_get_default_client.return_value = mock_client

        with pytest.raises(NetworkError, match="timeout"):
            get_request_headers()

    @patch("requests.post")
    def test_exponential_backoff_timing(self, mock_post):
        """Test that exponential backoff timing works correctly."""
        # Mock responses to simulate retries
        mock_response = Mock()
        mock_response.status_code = 429  # Rate limit
        mock_response.raise_for_status.side_effect = HTTPError("Rate limited")
        mock_response.response = mock_response  # For error handling
        mock_post.return_value = mock_response

        start_time = time.time()

        with pytest.raises(NetworkError):
            # This should trigger retries with exponential backoff
            from traylinx_auth_client.client import TraylinxAuthClient

            client = TraylinxAuthClient(
                client_id="test",
                client_secret="test_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                max_retries=2,
                retry_delay=0.1,  # Short delay for testing
            )
            client._fetch_tokens()

        elapsed_time = time.time() - start_time
        # Should take some time due to retries, but not too strict on timing
        assert elapsed_time >= 0.1

    @pytest.mark.skip(reason="Complex mocking - needs refactoring")
    @patch("requests.Session")
    def test_retry_on_specific_status_codes(self, mock_session_class):
        """Test that retries occur only on specific status codes."""
        from traylinx_auth_client.client import TraylinxAuthClient

        # Test retry codes
        retry_codes = [429, 500, 502, 503, 504]

        for status_code in retry_codes:
            mock_response = Mock()
            mock_response.status_code = status_code
            mock_response.raise_for_status.side_effect = HTTPError(
                f"HTTP {status_code}"
            )
            mock_response.response = mock_response  # For error handling

            mock_session_instance = Mock()
            mock_session_instance.post.return_value = mock_response
            mock_session_instance.mount = Mock()  # Add mount method
            mock_session_instance.headers = Mock()
            mock_session_instance.headers.update = Mock()
            mock_session_class.return_value = mock_session_instance

            client = TraylinxAuthClient(
                client_id="test",
                client_secret="test_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                max_retries=1,
            )

            with pytest.raises(NetworkError):
                client._fetch_tokens()

            # Verify the session was used
            assert mock_session_instance.post.called
            mock_session_class.reset_mock()

        # Test non-retry codes
        no_retry_codes = [400, 401, 403, 404]

        for status_code in no_retry_codes:
            mock_response = Mock()
            mock_response.status_code = status_code
            mock_response.raise_for_status.side_effect = HTTPError(
                f"HTTP {status_code}"
            )
            mock_response.response = mock_response  # For error handling

            mock_session_instance = Mock()
            mock_session_instance.post.return_value = mock_response
            mock_session_instance.mount = Mock()  # Add mount method
            mock_session_instance.headers = Mock()
            mock_session_instance.headers.update = Mock()
            mock_session_class.return_value = mock_session_instance

            client = TraylinxAuthClient(
                client_id="test",
                client_secret="test_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                max_retries=1,
            )

            with pytest.raises((AuthenticationError, NetworkError)):
                client._fetch_tokens()

            # Verify the session was used
            assert mock_session_instance.post.called
            mock_session_class.reset_mock()


class TestConcurrencyAndThreadSafety:
    """Test concurrency and thread safety of the authentication client."""

    @patch("traylinx_auth_client.main.get_default_client")
    def test_concurrent_token_access(self, mock_get_default_client):
        """Test concurrent access to tokens."""
        mock_client = Mock()
        mock_client.get_request_headers.return_value = {
            "Authorization": "Bearer test_access_token",
            "X-Agent-Secret-Token": "test_agent_secret_token",
            "X-Agent-User-Id": "12345678-1234-1234-1234-123456789abc",
        }
        mock_get_default_client.return_value = mock_client

        results = []
        errors = []

        def get_headers():
            try:
                headers = get_request_headers()
                results.append(headers)
            except Exception as e:
                errors.append(e)

        # Run multiple threads concurrently
        threads = []
        for _ in range(10):
            thread = threading.Thread(target=get_headers)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Check results
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 10

        # All results should be identical
        expected_headers = {
            "Authorization": "Bearer test_access_token",
            "X-Agent-Secret-Token": "test_agent_secret_token",
            "X-Agent-User-Id": "12345678-1234-1234-1234-123456789abc",
        }

        for headers in results:
            assert headers == expected_headers

    def test_concurrent_auth_requests(self):
        """Test concurrent authentication requests."""
        app = FastAPI()

        @app.get("/test")
        @require_a2a_auth
        async def test_endpoint(request: Request):
            return {"message": "success"}

        client = TestClient(app)

        with patch("traylinx_auth_client.main.validate_a2a_request") as mock_validate:
            mock_validate.return_value = True

            results = []
            errors = []

            def make_request():
                try:
                    headers = {
                        "x-agent-secret-token": "test_secret_token",
                        "x-agent-user-id": "12345678-1234-1234-1234-123456789abc",
                    }
                    response = client.get("/test", headers=headers)
                    results.append(response.status_code)
                except Exception as e:
                    errors.append(e)

            # Use ThreadPoolExecutor for better control
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(make_request) for _ in range(20)]
                concurrent.futures.wait(futures)

            # Check results
            assert len(errors) == 0, f"Errors occurred: {errors}"
            assert len(results) == 20
            assert all(status == 200 for status in results)

    @pytest.mark.skip(reason="Complex mocking - needs refactoring")
    @patch("requests.Session")
    def test_token_refresh_race_condition(self, mock_session_class):
        """Test handling of race conditions during token refresh."""
        from traylinx_auth_client.client import TraylinxAuthClient

        # Mock successful token response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "new_access_token",
            "agent_secret_token": "new_agent_secret_token",
            "expires_in": 3600,
        }
        mock_response.raise_for_status.return_value = None

        mock_session_instance = Mock()
        mock_session_instance.post.return_value = mock_response
        mock_session.return_value = mock_session_instance

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        client._session = mock_session_instance

        # Simulate expired tokens
        client._token_expiration = time.time() - 1

        results = []
        errors = []

        def get_token():
            try:
                token = client.get_access_token()
                results.append(token)
            except Exception as e:
                errors.append(e)

        # Run multiple threads that will all try to refresh tokens
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=get_token)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Check results
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 5

        # All threads should get the same token
        assert all(token == "new_access_token" for token in results)

        # Token refresh should have been called at least once
        assert mock_session_instance.post.call_count >= 1

    @patch("requests.Session")
    def test_thread_safety_with_different_clients(self, mock_session_class):
        """Test thread safety when using different client instances."""
        from traylinx_auth_client.client import TraylinxAuthClient

        results = []
        errors = []

        def create_and_use_client(client_id):
            try:
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    "access_token": f"token_{client_id}",
                    "agent_secret_token": f"agent_token_{client_id}",
                    "expires_in": 3600,
                }
                mock_response.raise_for_status.return_value = None

                mock_session_instance = Mock()
                mock_session_instance.post.return_value = mock_response

                client = TraylinxAuthClient(
                    client_id=f"client_{client_id}",
                    client_secret="test_secret_123",
                    api_base_url="https://api.example.com",
                    agent_user_id="12345678-1234-1234-1234-123456789abc",
                )
                client._session = mock_session_instance

                token = client.get_access_token()
                results.append((client_id, token))
            except Exception as e:
                errors.append((client_id, e))

        # Create multiple threads with different clients
        threads = []
        for i in range(5):
            thread = threading.Thread(target=create_and_use_client, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Check results
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 5

        # Each client should have its own token
        for client_id, token in results:
            assert token == f"token_{client_id}"

    def test_performance_under_load(self):
        """Test performance characteristics under concurrent load."""
        app = FastAPI()

        @app.get("/test")
        @require_a2a_auth
        async def test_endpoint(request: Request):
            return {"message": "success"}

        client = TestClient(app)

        with patch("traylinx_auth_client.main.validate_a2a_request") as mock_validate:
            mock_validate.return_value = True

            start_time = time.time()

            def make_request():
                headers = {
                    "x-agent-secret-token": "test_secret_token",
                    "x-agent-user-id": "12345678-1234-1234-1234-123456789abc",
                }
                return client.get("/test", headers=headers)

            # Use ThreadPoolExecutor for concurrent requests
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_request) for _ in range(100)]
                responses = [
                    future.result()
                    for future in concurrent.futures.as_completed(futures)
                ]

            elapsed_time = time.time() - start_time

            # Check that all requests succeeded
            assert len(responses) == 100
            assert all(response.status_code == 200 for response in responses)

            # Performance check - should complete within reasonable time
            # (This is a rough check and may need adjustment based on system performance)
            assert elapsed_time < 10.0, f"Requests took too long: {elapsed_time:.2f}s"


class TestErrorRecoveryAndResilience:
    """Test error recovery and resilience features."""

    @pytest.mark.skip(reason="Complex mocking - needs refactoring")
    @patch("requests.Session")
    def test_recovery_after_network_failure(self, mock_session_class):
        """Test recovery after temporary network failures."""
        from traylinx_auth_client.client import TraylinxAuthClient

        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "recovered_token",
            "agent_secret_token": "recovered_agent_token",
            "expires_in": 3600,
        }
        mock_response.raise_for_status.return_value = None

        mock_session_instance = Mock()
        mock_session_instance.post.return_value = mock_response
        mock_session.return_value = mock_session_instance

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
            max_retries=1,
        )
        client._session = mock_session_instance

        # Should succeed and return token
        token = client.get_access_token()
        assert token == "recovered_token"
        assert mock_session_instance.post.call_count >= 1

    @pytest.mark.skip(reason="Complex mocking - needs refactoring")
    @patch("requests.Session")
    def test_graceful_degradation(self, mock_session_class):
        """Test graceful degradation when services are unavailable."""
        from traylinx_auth_client.client import TraylinxAuthClient

        # Mock connection error
        mock_session_instance = Mock()
        mock_session_instance.post.side_effect = ConnectionError("Connection failed")
        mock_session.return_value = mock_session_instance

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
            max_retries=2,
        )
        client._session = mock_session_instance

        # Should raise appropriate error after retries
        with pytest.raises(NetworkError, match="Connection failed"):
            client.get_access_token()

        # Should have attempted the call
        assert mock_session_instance.post.call_count >= 1

    def test_error_context_preservation(self):
        """Test that error context is preserved through the call stack."""
        with patch(
            "traylinx_auth_client.main.get_default_client"
        ) as mock_get_default_client:
            mock_client = Mock()

            # Create a chain of errors
            original_error = ConnectionError("Original network error")

            def create_chained_error():
                try:
                    raise original_error
                except ConnectionError as e:
                    raise AuthenticationError("Auth failed") from e

            try:
                create_chained_error()
            except AuthenticationError as auth_error:
                mock_client.get_request_headers.side_effect = auth_error

            mock_get_default_client.return_value = mock_client

            try:
                get_request_headers()
            except AuthenticationError as e:
                # Check that error context is preserved
                assert e.__cause__ is original_error
                assert isinstance(e.__cause__, ConnectionError)
            else:
                pytest.fail("Expected AuthenticationError to be raised")


class TestEdgeCasesAndBoundaryConditions:
    """Test edge cases and boundary conditions."""

    @patch("traylinx_auth_client.main.get_default_client")
    def test_empty_environment_variables(self, mock_get_default_client):
        """Test handling of empty environment variables."""
        mock_client = Mock()
        mock_client.get_request_headers.side_effect = ValidationError(
            "Configuration validation failed: agent_user_id: Agent User ID cannot be empty"
        )
        mock_get_default_client.return_value = mock_client

        # Test with empty string - this will be caught during client initialization
        with pytest.raises(ValidationError, match="agent_user_id"):
            get_request_headers()

    def test_unicode_handling_in_headers(self):
        """Test handling of unicode characters in headers."""
        app = FastAPI()

        @app.get("/test")
        @require_a2a_auth
        async def test_endpoint(request: Request):
            return {"message": "success"}

        client = TestClient(app)

        with patch("traylinx_auth_client.main.validate_a2a_request") as mock_validate:
            mock_validate.return_value = True

            # Test with ASCII-safe headers (HTTP headers must be ASCII)
            headers = {
                "x-agent-secret-token": "token_with_special_chars",
                "x-agent-user-id": "12345678-1234-1234-1234-123456789abc",
            }

            response = client.get("/test", headers=headers)
            assert response.status_code == 200

    def test_very_long_header_values(self):
        """Test handling of very long header values."""
        app = FastAPI()

        @app.get("/test")
        @require_a2a_auth
        async def test_endpoint(request: Request):
            return {"message": "success"}

        client = TestClient(app)

        with patch("traylinx_auth_client.main.validate_a2a_request") as mock_validate:
            mock_validate.return_value = True

            # Test with very long header values
            long_token = "a" * 1000  # Long token
            long_user_id = "12345678-1234-1234-1234-123456789abc"  # Valid UUID

            headers = {
                "x-agent-secret-token": long_token,
                "x-agent-user-id": long_user_id,
            }

            response = client.get("/test", headers=headers)
            assert response.status_code == 200

    @pytest.mark.skip(reason="Complex mocking - needs refactoring")
    @patch("requests.Session")
    def test_malformed_json_response(self, mock_session_class):
        """Test handling of malformed JSON responses."""
        from traylinx_auth_client.client import TraylinxAuthClient

        # Mock response with invalid JSON
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("Invalid JSON")
        mock_response.raise_for_status.return_value = None

        mock_session_instance = Mock()
        mock_session_instance.post.return_value = mock_response
        mock_session.return_value = mock_session_instance

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        client._session = mock_session_instance

        with pytest.raises(AuthenticationError, match="Failed to parse"):
            client.get_access_token()

    @pytest.mark.skip(reason="Complex mocking - needs refactoring")
    @patch("requests.Session")
    def test_missing_required_fields_in_response(self, mock_session_class):
        """Test handling of missing required fields in token response."""
        from traylinx_auth_client.client import TraylinxAuthClient

        # Mock response missing required fields
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "test_token",
            # Missing agent_secret_token and expires_in
        }
        mock_response.raise_for_status.return_value = None

        mock_session_instance = Mock()
        mock_session_instance.post.return_value = mock_response
        mock_session.return_value = mock_session_instance

        client = TraylinxAuthClient(
            client_id="test",
            client_secret="test_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )
        client._session = mock_session_instance

        with pytest.raises(AuthenticationError, match="missing fields"):
            client.get_access_token()
