import pytest
from unittest.mock import patch, MagicMock
import time
from traylinx_auth_client.token_manager import TokenManager


@pytest.fixture(autouse=True)
def reset_singleton():
    TokenManager._instance = None


@pytest.fixture
def mock_env_vars(monkeypatch):
    monkeypatch.setenv("TRAYLINX_CLIENT_ID", "test_client_id")
    monkeypatch.setenv("TRAYLINX_CLIENT_SECRET", "test_client_secret")
    monkeypatch.setenv("TRAYLINX_API_BASE_URL", "https://test.com")


@patch("requests.post")
def test_fetch_tokens(mock_post, mock_env_vars):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "test_access_token",
        "agent_secret_token": "test_agent_secret_token",
        "expires_in": 3600,
    }
    mock_post.return_value = mock_response

    token_manager = TokenManager()
    token_manager._fetch_tokens()

    assert token_manager.access_token == "test_access_token"
    assert token_manager.agent_secret_token == "test_agent_secret_token"


@patch("requests.post")
def test_get_access_token_fetches_new_token_if_expired(mock_post, mock_env_vars):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "new_access_token",
        "agent_secret_token": "new_agent_secret_token",
        "expires_in": 3600,
    }
    mock_post.return_value = mock_response

    token_manager = TokenManager()
    token_manager.token_expiration = time.time() - 1  # Expired

    access_token = token_manager.get_access_token()

    assert access_token == "new_access_token"
    mock_post.assert_called_once()


def test_token_manager_is_singleton(mock_env_vars):
    tm1 = TokenManager()
    tm2 = TokenManager()
    assert tm1 is tm2
