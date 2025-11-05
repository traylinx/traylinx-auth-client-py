import pytest
from unittest.mock import patch, MagicMock
import requests_mock
from traylinx_auth_client.services import IntrospectionService
from traylinx_auth_client.token_manager import TokenManager


@pytest.fixture(autouse=True)
def reset_singleton():
    TokenManager._instance = None


@pytest.fixture
def mock_env_vars(monkeypatch):
    monkeypatch.setenv("TRAYLINX_CLIENT_ID", "test_client_id")
    monkeypatch.setenv("TRAYLINX_CLIENT_SECRET", "test_client_secret_123")
    monkeypatch.setenv("TRAYLINX_API_BASE_URL", "https://test.com")
    monkeypatch.setenv("TRAYLINX_AGENT_USER_ID", "12345678-1234-1234-1234-123456789abc")


@pytest.fixture
def mock_auth_service(requests_mock):
    requests_mock.post(
        "https://test.com/oauth/token",  # Token manager doesn't normalize URLs
        json={
            "access_token": "mock_access_token",
            "agent_secret_token": "mock_agent_secret_token",
            "expires_in": 3600,
        },
        status_code=200,
    )


def test_validate_token_success(mock_env_vars, mock_auth_service, requests_mock):
    requests_mock.post(
        "https://test.com/oauth/agent/introspect",  # Services use token manager URLs
        json={"active": True},
        status_code=200,
    )

    service = IntrospectionService()
    is_valid = service.validate_token(
        "test_secret_token", "12345678-1234-1234-1234-123456789abc"
    )

    assert is_valid is True


def test_validate_token_failure(mock_env_vars, mock_auth_service, requests_mock):
    requests_mock.post(
        "https://test.com/oauth/agent/introspect",  # Services use token manager URLs
        json={"active": False},
        status_code=200,
    )

    service = IntrospectionService()
    is_valid = service.validate_token(
        "test_secret_token", "12345678-1234-1234-1234-123456789abc"
    )

    assert is_valid is False


def test_validate_token_http_error(mock_env_vars, mock_auth_service, requests_mock):
    requests_mock.post(
        "https://test.com/oauth/agent/introspect",  # Services use token manager URLs
        status_code=500,
    )

    service = IntrospectionService()
    is_valid = service.validate_token(
        "test_secret_token", "12345678-1234-1234-1234-123456789abc"
    )

    assert is_valid is False
