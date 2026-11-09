"""
High-level functions and decorators for Traylinx A2A authentication.

This module provides convenient functions and decorators for common authentication
tasks, including making authenticated requests, protecting endpoints, and validating
incoming requests.
"""

from functools import wraps
from threading import Lock
import requests
from typing import Dict, Any, Optional, Union
from .client import TraylinxAuthClient
from .security import destination, credentials_from, outbound_options
from .transport import SecureSession
from .exceptions import TraylinxAuthError

# Default client instance
_default_client = None
_default_client_lock = Lock()


def get_default_client() -> TraylinxAuthClient:
    """Get or create the default TraylinxAuthClient instance.

    This function implements a singleton pattern for the default client,
    creating it on first access using environment variables.

    Returns:
        TraylinxAuthClient: The default client instance

    Note:
        The client is created using environment variables:
        - TRAYLINX_CLIENT_ID
        - TRAYLINX_CLIENT_SECRET
        - TRAYLINX_API_BASE_URL
        - TRAYLINX_AGENT_USER_ID
    """
    global _default_client
    with _default_client_lock:
        if _default_client is None:
            _default_client = TraylinxAuthClient()
        return _default_client


def get_request_headers() -> Dict[str, str]:
    """Get headers for calling the Traylinx auth service.

    Returns headers that include both access_token and agent_secret_token,
    suitable for making requests to Traylinx Sentinel API endpoints.

    Returns:
        Dict[str, str]: Headers dictionary containing:
            - Authorization: Bearer <access_token>
            - X-Agent-Secret-Token: <agent_secret_token>
            - X-Agent-User-Id: <agent_user_id>

    Raises:
        ValidationError: If client configuration is invalid
        AuthenticationError: If token acquisition fails
        NetworkError: If network issues occur during token fetch

    Example:
        >>> headers = get_request_headers()
        >>> response = requests.get("https://auth.traylinx.com/a2a/rpc", headers=headers)
    """
    return get_default_client().get_request_headers()


def get_agent_request_headers() -> Dict[str, str]:
    """Get headers for calling other agents (agent-to-agent communication).

    Returns headers that include ONLY the agent_secret_token, suitable for
    making requests to other Traylinx agents.

    Returns:
        Dict[str, str]: Headers dictionary containing:
            - X-Agent-Secret-Token: <agent_secret_token>
            - X-Agent-User-Id: <agent_user_id>

    Raises:
        ValidationError: If client configuration is invalid
        AuthenticationError: If token acquisition fails
        NetworkError: If network issues occur during token fetch

    Example:
        >>> headers = get_agent_request_headers()
        >>> response = requests.post("https://other-agent.com/api", headers=headers)
    """
    return get_default_client().get_agent_request_headers()


def validate_a2a_request(headers: Dict[str, str]) -> bool:
    auth = credentials_from(headers, dual=False)
    return get_default_client().validate_token(auth[0], auth[1]) if auth else False


def require_a2a_auth(func):
    from fastapi import HTTPException
    from starlette.requests import Request
    from starlette.concurrency import run_in_threadpool

    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = next((v for v in (*args, *kwargs.values()) if isinstance(v, Request)), None)
        if request is None:
            raise HTTPException(status_code=500, detail="Request object missing")
        try:
            # No blocking requests I/O on the ASGI event loop.
            valid = await run_in_threadpool(validate_a2a_request, request.headers)
        except Exception:
            raise HTTPException(status_code=503, detail="Authentication service unavailable") from None
        if not valid:
            raise HTTPException(status_code=401, detail="Invalid or missing A2A authentication")
        return await func(*args, **kwargs)  # Preserve downstream exceptions.
    return wrapper


def a2a_request(method: str = "GET", url: str = None, **kwargs):
    """Decorator for making authenticated A2A requests to other agents.

    This decorator allows you to declaratively specify HTTP requests that should
    be made with A2A authentication. The decorated function is called first,
    then the HTTP request is made with the specified parameters.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        url: Target agent's URL
        **kwargs: Additional arguments for requests.request()

    Returns:
        Decorator function that makes authenticated requests

    Example:
        >>> @a2a_request("GET", "https://other-agent.example/api/data")
        >>> def get_data():
        ...     # This function runs first, then the GET request is made
        ...     print("Fetching data from other agent")
        >>>
        >>> @a2a_request("POST", "https://other-agent.example/api/process")
        >>> def process_data(data):
        ...     # Function logic here, then POST request with authentication
        ...     return {"processed": True}

    Note:
        The decorated function's return value is ignored. The decorator
        returns the JSON response from the HTTP request.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **func_kwargs):
            # Validate before executing user code or obtaining credentials.
            destination(url)
            outbound_options(kwargs)
            func(*args, **func_kwargs)
            return make_a2a_request(method, url, **kwargs)

        return wrapper

    return decorator


def make_a2a_request(method: str, url: str, **kwargs) -> Dict[str, Any]:
    destination(url)  # Reject before obtaining credentials.
    options = outbound_options(kwargs)
    headers = dict(options.pop("headers"), **get_agent_request_headers())
    try:
        with SecureSession() as session:
            response = session.request(method, url, headers=headers, **options)
            response.raise_for_status()
            return response.json()
    except TraylinxAuthError:
        raise
    except Exception as error:
        get_default_client()._handle_request_error(error, "agent request")


# A2A Extension Functions
def get_a2a_request_headers() -> Dict[str, str]:
    """Get A2A-compatible authentication headers using Bearer token format.

    Returns headers in the standard A2A format using Bearer token authentication,
    which is compatible with the broader A2A ecosystem.

    Returns:
        Dict[str, str]: Headers dictionary containing:
            - Authorization: Bearer <agent_secret_token>
            - X-Agent-User-Id: <agent_user_id>

    Raises:
        ValidationError: If client configuration is invalid
        AuthenticationError: If token acquisition fails
        NetworkError: If network issues occur during token fetch

    Example:
        >>> headers = get_a2a_request_headers()
        >>> response = requests.get("https://a2a-agent.com/api", headers=headers)

    Note:
        This format uses the agent_secret_token in the Authorization header
        as a Bearer token, following A2A standard conventions.
    """
    return get_default_client().get_a2a_headers()


def validate_dual_auth_request(headers: Dict[str, str]) -> bool:
    """Validate incoming requests supporting both Bearer tokens and custom headers.

    This function provides dual-mode authentication validation, supporting both:
    1. A2A standard format: Authorization: Bearer {agent_secret_token}
    2. TraylinxAuth custom format: X-Agent-Secret-Token: {agent_secret_token}

    Exactly one credential format is required. Mixed formats are rejected;
    failed verification never falls back to another credential.

    Args:
        headers: Dictionary of request headers (case-insensitive)

    Returns:
        bool: True if authentication is valid using either format, False otherwise

    Raises:
        AuthenticationError: If validation request to auth service fails
        NetworkError: If network issues occur during validation

    Example:
        >>> # Works with Bearer token format
        >>> headers1 = {
        ...     "Authorization": "Bearer agent-secret-token",
        ...     "X-Agent-User-Id": "agent-id"
        ... }
        >>> is_valid = validate_dual_auth_request(headers1)
        >>>
        >>> # Also works with custom header format
        >>> headers2 = {
        ...     "X-Agent-Secret-Token": "agent-secret-token",
        ...     "X-Agent-User-Id": "agent-id"
        ... }
        >>> is_valid = validate_dual_auth_request(headers2)

    Note:
        This function enables gradual migration from custom headers to
        standard Bearer token format while maintaining backward compatibility.
    """
    return get_default_client().validate_a2a_request(headers)


def detect_auth_mode(headers: Dict[str, str]) -> str:
    """Detect authentication mode from request headers.

    Analyzes request headers to determine which authentication format is being used.
    This is useful for logging, monitoring, and debugging authentication issues.

    Args:
        headers: Dictionary of request headers (case-insensitive)

    Returns:
        str: Authentication mode detected:
            - 'bearer': Authorization header with Bearer token
            - 'custom': X-Agent-Secret-Token custom header
            - 'none': No authentication headers detected

    Example:
        >>> headers = {"Authorization": "Bearer token123", "X-Agent-User-Id": "agent1"}
        >>> mode = detect_auth_mode(headers)
        >>> print(mode)  # Output: 'bearer'
        >>>
        >>> headers = {"X-Agent-Secret-Token": "token123", "X-Agent-User-Id": "agent1"}
        >>> mode = detect_auth_mode(headers)
        >>> print(mode)  # Output: 'custom'

    Note:
        This function only detects the presence of authentication headers,
        it does not validate their correctness or authenticity.
    """
    return get_default_client().detect_auth_mode(headers)


def require_dual_auth(func):
    from fastapi import HTTPException
    from starlette.requests import Request
    from starlette.concurrency import run_in_threadpool

    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = next((v for v in (*args, *kwargs.values()) if isinstance(v, Request)), None)
        if request is None:
            raise HTTPException(status_code=500, detail="Request object missing")
        try:
            # No blocking requests I/O on the ASGI event loop.
            valid = await run_in_threadpool(validate_dual_auth_request, request.headers)
        except Exception:
            raise HTTPException(status_code=503, detail="Authentication service unavailable") from None
        if not valid:
            raise HTTPException(status_code=401, detail="Invalid or missing authentication")
        return await func(*args, **kwargs)  # Preserve downstream exceptions.
    return wrapper
