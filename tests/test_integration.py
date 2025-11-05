import pytest
import requests_mock
from urllib.parse import parse_qs
from unittest.mock import patch, Mock
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from traylinx_auth_client.main import get_request_headers, require_a2a_auth
from traylinx_auth_client.token_manager import TokenManager

# 1. Create a simple FastAPI app for testing
app = FastAPI()


@app.post("/protected")
@require_a2a_auth
async def protected_route(request: Request):
    """A test endpoint protected by our decorator."""
    return {"message": "success"}


client = TestClient(app)


# 2. Fixture to reset the TokenManager singleton before each test
@pytest.fixture(autouse=True)
def reset_singleton():
    """Ensures each test gets a fresh TokenManager instance."""
    TokenManager._instance = None
    yield


# 3. Fixture to set up necessary environment variables
@pytest.fixture
def mock_env_vars(monkeypatch):
    """Sets all required environment variables for the client."""
    monkeypatch.setenv("TRAYLINX_CLIENT_ID", "test_client_id")
    monkeypatch.setenv("TRAYLINX_CLIENT_SECRET", "test_client_secret_123")
    monkeypatch.setenv("TRAYLINX_API_BASE_URL", "https://mock-auth.traylinx.com")
    monkeypatch.setenv("TRAYLINX_AGENT_USER_ID", "12345678-1234-1234-1234-123456789abc")


@patch("traylinx_auth_client.main.validate_a2a_request")
def test_full_flow_success(mock_validate, mock_env_vars, requests_mock):
    """
    Tests the complete end-to-end flow for a successful request.
    1. `get_request_headers()` is called.
    2. It fetches a new set of tokens from the mocked `/oauth/token` endpoint.
    3. A request is made to the `/protected` endpoint with these headers.
    4. The `@require_a2a_auth` decorator receives the request.
    5. It calls the mocked validation function (validate_a2a_request).
    6. Validation succeeds, and the request is allowed.
    """
    # Mock the Sentinel API endpoints for token fetching
    requests_mock.post(
        "https://mock-auth.traylinx.com/oauth/token",
        json={
            "access_token": "new_access_token",
            "agent_secret_token": "new_secret_token",
            "expires_in": 3600,
        },
        status_code=200,
    )

    # Mock the validation function to return True
    mock_validate.return_value = True

    # Get the headers that a real agent would use
    headers = get_request_headers()

    # Make a request to our test app's protected endpoint
    response = client.post("/protected", headers=headers)

    # Assert the request was successful
    assert response.status_code == 200
    assert response.json() == {"message": "success"}

    # Verify that validation was called
    assert mock_validate.called
    assert len(requests_mock.request_history) == 1  # Only token fetch


@patch("traylinx_auth_client.main.validate_a2a_request")
def test_full_flow_introspection_fails(mock_validate, mock_env_vars, requests_mock):
    """
    Tests the complete end-to-end flow for a request where introspection fails.
    """
    # Mock the Sentinel API endpoints for token fetching
    requests_mock.post(
        "https://mock-auth.traylinx.com/oauth/token",
        json={
            "access_token": "another_access_token",
            "agent_secret_token": "another_secret_token",
            "expires_in": 3600,
        },
        status_code=200,
    )

    # Mock the validation function to return False (authentication fails)
    mock_validate.return_value = False

    # Get the headers
    headers = get_request_headers()

    # Make the request
    response = client.post("/protected", headers=headers)

    # Assert the request was denied with a 401 status
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing A2A authentication"}
    
    # Verify that validation was called
    assert mock_validate.called
