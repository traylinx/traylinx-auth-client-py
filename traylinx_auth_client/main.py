"""
High-level functions and decorators for Traylinx A2A authentication.

This module provides convenient functions and decorators for common authentication
tasks, including making authenticated requests, protecting endpoints, and validating
incoming requests.
"""

from functools import wraps
import requests
from typing import Dict, Any, Optional, Union
from .client import TraylinxAuthClient

# Default client instance
_default_client = None


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
    """Validate an incoming A2A request using custom header format.

    Validates incoming requests that use the custom header format:
    - X-Agent-Secret-Token: <token>
    - X-Agent-User-Id: <agent_id>

    Args:
        headers: Dictionary of request headers (case-insensitive)

    Returns:
        bool: True if the request is valid and authenticated, False otherwise

    Raises:
        AuthenticationError: If validation request to auth service fails
        NetworkError: If network issues occur during validation

    Example:
        >>> from fastapi import Request
        >>>
        >>> @app.post("/endpoint")
        >>> async def my_endpoint(request: Request):
        ...     if not validate_a2a_request(request.headers):
        ...         raise HTTPException(status_code=401, detail="Unauthorized")
        ...     return {"message": "Authenticated"}

    Note:
        This function uses case-insensitive header lookup and validates
        the token against the Traylinx Sentinel API.
    """
    agent_secret_token = headers.get("x-agent-secret-token")
    agent_user_id = headers.get("x-agent-user-id")

    if not agent_secret_token or not agent_user_id:
        return False

    return get_default_client().validate_token(agent_secret_token, agent_user_id)


def require_a2a_auth(func):
    """Decorator for protecting FastAPI endpoints with A2A authentication.

    This decorator automatically validates incoming requests using the custom
    header format (X-Agent-Secret-Token) and raises HTTP 401 if authentication
    fails.

    Args:
        func: The FastAPI endpoint function to protect

    Returns:
        Decorated function that performs authentication before calling the original

    Raises:
        HTTPException: 401 status if authentication fails or is missing

    Example:
        >>> from fastapi import FastAPI, Request
        >>> from traylinx_auth_client import require_a2a_auth
        >>>
        >>> app = FastAPI()
        >>>
        >>> @app.get("/protected")
        >>> @require_a2a_auth
        >>> async def protected_endpoint(request: Request):
        ...     return {"message": "This endpoint requires A2A authentication"}

    Note:
        The function must have a parameter with type annotation `Request` or a
        parameter named `request` or `http_request` to access request headers.
    """
    from starlette.requests import Request as StarletteRequest

    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Find the Request object in positional args or keyword args
        http_request = None

        # Check positional arguments
        for arg in args:
            if isinstance(arg, StarletteRequest):
                http_request = arg
                break

        # Check keyword arguments if not found
        if http_request is None:
            for key in ["request", "http_request", "req"]:
                if key in kwargs and isinstance(kwargs[key], StarletteRequest):
                    http_request = kwargs[key]
                    break

        # If still not found, check all kwargs values
        if http_request is None:
            for value in kwargs.values():
                if isinstance(value, StarletteRequest):
                    http_request = value
                    break

        if http_request is None:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=500,
                detail="Internal error: Request object not found in endpoint parameters",
            )

        try:
            if not validate_a2a_request(http_request.headers):
                from fastapi import HTTPException

                raise HTTPException(
                    status_code=401, detail="Invalid or missing A2A authentication"
                )
        except HTTPException:
            raise
        except Exception as e:
            # Log the actual error for debugging, but return generic 401
            import logging

            logging.getLogger(__name__).error(f"A2A auth validation error: {e}")
            from fastapi import HTTPException

            raise HTTPException(
                status_code=401, detail="Invalid or missing A2A authentication"
            )

        return await func(*args, **kwargs)

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
        >>> @a2a_request("GET", "http://other-agent:8000/api/data")
        >>> def get_data():
        ...     # This function runs first, then the GET request is made
        ...     print("Fetching data from other agent")
        >>>
        >>> @a2a_request("POST", "http://other-agent:8000/api/process")
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
            # Get the result from the original function
            result = func(*args, **func_kwargs)

            # Make the authenticated request
            headers = get_agent_request_headers()

            # Merge any additional headers from kwargs
            if "headers" in kwargs:
                headers.update(kwargs["headers"])

            # Prepare request parameters
            request_kwargs = {
                "headers": headers,
                **{k: v for k, v in kwargs.items() if k != "headers"},
            }

            # Make the request
            response = requests.request(method, url, **request_kwargs)
            response.raise_for_status()

            return response.json()

        return wrapper

    return decorator


def make_a2a_request(method: str, url: str, **kwargs) -> Dict[str, Any]:
    """Make an authenticated A2A request to another agent.

    This is the primary function for making authenticated requests to other
    Traylinx agents. It automatically adds the required authentication headers
    and handles the HTTP request.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
        url: Target agent's URL (must be a valid HTTP/HTTPS URL)
        **kwargs: Additional arguments passed to requests.request(), such as:
            - json: JSON data to send in request body
            - data: Form data to send in request body
            - params: URL parameters
            - timeout: Request timeout in seconds
            - headers: Additional headers (merged with auth headers)

    Returns:
        Dict[str, Any]: JSON response from the target agent

    Raises:
        ValidationError: If client configuration is invalid
        AuthenticationError: If token acquisition fails
        NetworkError: If network issues occur
        requests.HTTPError: If the HTTP request fails (4xx, 5xx status codes)
        requests.JSONDecodeError: If response is not valid JSON

    Example:
        >>> # Simple GET request
        >>> data = make_a2a_request("GET", "https://other-agent.com/api/users")
        >>>
        >>> # POST request with JSON data
        >>> result = make_a2a_request(
        ...     "POST",
        ...     "https://other-agent.com/api/process",
        ...     json={"items": ["item1", "item2"]},
        ...     timeout=60
        ... )
        >>>
        >>> # PUT request with custom headers
        >>> response = make_a2a_request(
        ...     "PUT",
        ...     "https://other-agent.com/api/update/123",
        ...     json={"status": "completed"},
        ...     headers={"X-Custom-Header": "value"}
        ... )

    Note:
        This function uses agent-to-agent authentication headers (X-Agent-Secret-Token)
        and does NOT include the access_token. For calling Traylinx auth service
        endpoints, use the TraylinxAuthClient methods directly.
    """
    headers = get_agent_request_headers()

    # Merge any additional headers
    if "headers" in kwargs:
        headers.update(kwargs["headers"])
        del kwargs["headers"]

    response = requests.request(method, url, headers=headers, **kwargs)
    response.raise_for_status()

    return response.json()


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

    The function tries Bearer token format first, then falls back to custom
    headers for backward compatibility.

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
    """Enhanced decorator supporting both Bearer tokens and custom headers.

    This decorator provides flexible authentication that accepts both A2A standard
    Bearer token format and TraylinxAuth custom header format. It's useful for
    endpoints that need to support multiple authentication methods during
    migration periods.

    Args:
        func: The FastAPI endpoint function to protect

    Returns:
        Decorated function that performs dual-mode authentication

    Raises:
        HTTPException: 401 status if authentication fails with both formats

    Example:
        >>> @app.post("/flexible-endpoint")
        >>> @require_dual_auth
        >>> async def flexible_endpoint(request: Request):
        ...     # This endpoint accepts both authentication formats:
        ...     # 1. Authorization: Bearer {token}
        ...     # 2. X-Agent-Secret-Token: {token}
        ...     auth_mode = detect_auth_mode(request.headers)
        ...     return {"auth_mode": auth_mode, "message": "Authenticated"}

    Note:
        This decorator is particularly useful during migration from custom
        headers to standard Bearer token format, allowing gradual adoption.
    """
    from starlette.requests import Request as StarletteRequest

    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Find the Request object in positional args or keyword args
        http_request = None

        # Check positional arguments
        for arg in args:
            if isinstance(arg, StarletteRequest):
                http_request = arg
                break

        # Check keyword arguments if not found
        if http_request is None:
            for key in ["request", "http_request", "req"]:
                if key in kwargs and isinstance(kwargs[key], StarletteRequest):
                    http_request = kwargs[key]
                    break

        # If still not found, check all kwargs values
        if http_request is None:
            for value in kwargs.values():
                if isinstance(value, StarletteRequest):
                    http_request = value
                    break

        if http_request is None:
            from fastapi import HTTPException

            raise HTTPException(
                status_code=500,
                detail="Internal error: Request object not found in endpoint parameters",
            )

        if not validate_dual_auth_request(http_request.headers):
            from fastapi import HTTPException

            raise HTTPException(
                status_code=401, detail="Invalid or missing authentication"
            )

        return await func(*args, **kwargs)

    return wrapper
