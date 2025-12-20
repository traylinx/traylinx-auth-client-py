import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import time
from threading import Lock
import uuid
from typing import Dict, Optional, Any
from .config import AuthConfig, validate_config
from pydantic import ValidationError as PydanticValidationError
from .exceptions import (
    TraylinxAuthError,
    AuthenticationError,
    TokenExpiredError,
    NetworkError,
    ValidationError,
)


class TraylinxAuthClient:
    """Enterprise-grade Traylinx A2A authentication client.

    This client provides secure, thread-safe authentication for Traylinx Agent-to-Agent
    communication. It handles dual-token authentication, automatic token refresh,
    retry logic with exponential backoff, and comprehensive error handling.

    The client manages two types of tokens:
    - access_token: Used for calling Traylinx Sentinel API endpoints
    - agent_secret_token: Used for agent-to-agent communication

    Features:
    - Automatic token management with thread-safe caching
    - Configurable retry logic with exponential backoff
    - Connection pooling for improved performance
    - Comprehensive input validation using Pydantic
    - Custom exception hierarchy for better error handling
    - Support for both custom headers and A2A Bearer token formats

    Thread Safety:
        This class is thread-safe and can be safely used across multiple threads.
        Token management operations are protected with locks to prevent race conditions.

    Example:
        >>> # Basic usage with environment variables
        >>> client = TraylinxAuthClient()
        >>>
        >>> # Custom configuration
        >>> client = TraylinxAuthClient(
        ...     client_id="your-client-id",
        ...     client_secret="your-client-secret",
        ...     api_base_url="https://auth.traylinx.com",
        ...     agent_user_id="12345678-1234-1234-1234-123456789abc",
        ...     timeout=60,
        ...     max_retries=5
        ... )
        >>>
        >>> # Context manager usage (recommended)
        >>> with TraylinxAuthClient() as client:
        ...     response = client.rpc_health_check()
    """

    def __init__(
        self,
        client_id=None,
        client_secret=None,
        api_base_url=None,
        agent_user_id=None,
        timeout=30,
        max_retries=3,
        retry_delay=1.0,
        cache_tokens=True,
        log_level="INFO",
    ):
        """Initialize TraylinxAuthClient with comprehensive input validation.

        Creates a new client instance with the specified configuration. All parameters
        can be provided explicitly or via environment variables. The client performs
        comprehensive validation of all parameters using Pydantic models.

        Args:
            client_id (str, optional): OAuth client ID. Defaults to TRAYLINX_CLIENT_ID env var.
                Must contain only alphanumeric characters, hyphens, and underscores.
            client_secret (str, optional): OAuth client secret. Defaults to TRAYLINX_CLIENT_SECRET env var.
                Must be at least 10 characters long for security.
            api_base_url (str, optional): Base URL for Traylinx API. Defaults to TRAYLINX_API_BASE_URL env var.
                Must be a valid HTTPS URL.
            agent_user_id (str, optional): Agent user UUID. Defaults to TRAYLINX_AGENT_USER_ID env var.
                Must be a valid UUID format (e.g., "12345678-1234-1234-1234-123456789abc").
            timeout (int, optional): Request timeout in seconds. Defaults to 30.
                Must be between 1 and 300 seconds.
            max_retries (int, optional): Maximum retry attempts for failed requests. Defaults to 3.
                Must be between 0 and 10.
            retry_delay (float, optional): Base delay between retries in seconds. Defaults to 1.0.
                Used for exponential backoff calculation. Must be between 0.1 and 60.0.
            cache_tokens (bool, optional): Whether to cache tokens in memory. Defaults to True.
                When False, tokens are fetched for every request (not recommended for production).
            log_level (str, optional): Logging level. Defaults to "INFO".
                Valid values: "DEBUG", "INFO", "WARN", "ERROR".

        Raises:
            ValidationError: If any configuration parameter is invalid. The error message
                will contain detailed information about which parameters failed validation
                and why.

        Environment Variables:
            The following environment variables are used as defaults:
            - TRAYLINX_CLIENT_ID: OAuth client identifier
            - TRAYLINX_CLIENT_SECRET: OAuth client secret
            - TRAYLINX_API_BASE_URL: Traylinx Sentinel API base URL
            - TRAYLINX_AGENT_USER_ID: Agent user identifier (UUID format)

        Example:
            >>> # Using environment variables
            >>> client = TraylinxAuthClient()
            >>>
            >>> # Explicit configuration
            >>> client = TraylinxAuthClient(
            ...     client_id="my-agent-client",
            ...     client_secret="super-secret-key-123",
            ...     api_base_url="https://auth.traylinx.com",
            ...     agent_user_id="550e8400-e29b-41d4-a716-446655440000",
            ...     timeout=60,
            ...     max_retries=5,
            ...     retry_delay=2.0
            ... )

        Note:
            For production use, it's recommended to use environment variables
            rather than hard-coding credentials in your application code.
        """
        # Get values from parameters or environment variables
        config_params = {
            "client_id": client_id or os.getenv("TRAYLINX_CLIENT_ID"),
            "client_secret": client_secret or os.getenv("TRAYLINX_CLIENT_SECRET"),
            "api_base_url": api_base_url or os.getenv("TRAYLINX_API_BASE_URL"),
            "agent_user_id": agent_user_id or os.getenv("TRAYLINX_AGENT_USER_ID"),
            "timeout": timeout,
            "max_retries": max_retries,
            "retry_delay": retry_delay,
            "cache_tokens": cache_tokens,
            "log_level": log_level,
        }

        # Validate configuration
        try:
            self.config = validate_config(**config_params)
        except (ValueError, PydanticValidationError) as e:
            # Convert Pydantic validation errors to our custom ValidationError
            if isinstance(e, PydanticValidationError):
                # Extract detailed error messages from Pydantic validation error
                error_messages = []
                for error in e.errors():
                    field = ".".join(str(loc) for loc in error["loc"])
                    message = error["msg"]
                    error_messages.append(f"{field}: {message}")

                detailed_message = "; ".join(error_messages)
                error_message = f"Configuration validation failed: {detailed_message}"
            else:
                error_message = str(e)

            raise ValidationError(
                error_message, error_code="CONFIG_VALIDATION_ERROR", status_code=400
            )

        # Set instance attributes from validated config
        self.client_id = self.config.client_id
        self.client_secret = self.config.client_secret
        self.api_base_url = str(self.config.api_base_url)
        self.agent_user_id = self.config.agent_user_id

        self._access_token = None
        self._agent_secret_token = None
        self._token_expiration = 0
        self._lock = Lock()

        # Initialize session with retry configuration
        self._session = self._create_session_with_retries()

    def _create_session_with_retries(self) -> requests.Session:
        """Create a requests session with retry configuration and connection pooling.

        Returns:
            Configured requests.Session with retry logic and connection pooling
        """
        session = requests.Session()

        # Configure retry strategy with exponential backoff
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.retry_delay,
            status_forcelist=[
                429,
                500,
                502,
                503,
                504,
            ],  # Retry on these HTTP status codes
            allowed_methods=[
                "HEAD",
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "OPTIONS",
                "TRACE",
            ],
            raise_on_status=False,  # Don't raise exception on retry-able status codes
        )

        # Create HTTP adapter with retry strategy
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,  # Connection pooling
            pool_maxsize=20,
        )

        # Mount adapter for both HTTP and HTTPS
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set default headers
        session.headers.update({"User-Agent": "TraylinxAuthClient-Python/1.0.0"})

        return session

    def close(self):
        """Close the HTTP session and clean up resources."""
        if hasattr(self, "_session") and self._session:
            self._session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - clean up resources."""
        self.close()

    def _handle_request_error(self, error: Exception, context: str = "request") -> None:
        """Handle and convert requests exceptions to custom exceptions.

        Args:
            error: The original exception from requests
            context: Description of what operation was being performed

        Raises:
            NetworkError: For network-related issues
            AuthenticationError: For authentication failures
            TraylinxAuthError: For other unexpected errors
        """
        if isinstance(error, requests.exceptions.Timeout):
            raise NetworkError(
                f"Request timeout during {context}. Check network connectivity and consider increasing timeout.",
                error_code="TIMEOUT",
                status_code=408,
            )
        elif isinstance(error, requests.exceptions.ConnectionError):
            raise NetworkError(
                f"Connection failed during {context}. Check network connectivity and API URL.",
                error_code="CONNECTION_ERROR",
                status_code=0,
            )
        elif isinstance(error, requests.exceptions.HTTPError):
            response = error.response
            status_code = response.status_code

            if status_code == 401:
                raise AuthenticationError(
                    f"Authentication failed during {context}. Check client credentials.",
                    error_code="INVALID_CREDENTIALS",
                    status_code=401,
                )
            elif status_code == 429:
                raise NetworkError(
                    f"Rate limit exceeded during {context}. Please retry after some time.",
                    error_code="RATE_LIMIT",
                    status_code=429,
                )
            elif 500 <= status_code < 600:
                raise NetworkError(
                    f"Server error ({status_code}) during {context}. The service may be temporarily unavailable.",
                    error_code="SERVER_ERROR",
                    status_code=status_code,
                )
            else:
                raise NetworkError(
                    f"HTTP error ({status_code}) during {context}: {response.text}",
                    error_code="HTTP_ERROR",
                    status_code=status_code,
                )
        else:
            raise TraylinxAuthError(
                f"Unexpected error during {context}: {str(error)}",
                error_code="UNKNOWN_ERROR",
            )

    def _fetch_tokens(self):
        with self._lock:
            if self._token_expiration > time.time():
                return

            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "a2a",
            }

            try:
                response = self._session.post(
                    f"{self.api_base_url.rstrip('/')}/oauth/token",
                    data=data,
                    timeout=self.config.timeout,
                )
                response.raise_for_status()
                token_data = response.json()

                # Validate token response structure
                required_fields = ["access_token", "agent_secret_token", "expires_in"]
                missing_fields = [
                    field for field in required_fields if field not in token_data
                ]
                if missing_fields:
                    raise AuthenticationError(
                        f"Invalid token response: missing fields {missing_fields}",
                        error_code="MALFORMED_TOKEN_RESPONSE",
                        status_code=200,
                    )

                self._access_token = token_data["access_token"]
                self._agent_secret_token = token_data["agent_secret_token"]
                self._token_expiration = time.time() + token_data["expires_in"]

            except requests.exceptions.RequestException as e:
                self._handle_request_error(e, "token fetch")
            except (KeyError, ValueError, TypeError) as e:
                raise AuthenticationError(
                    f"Failed to parse token response: {str(e)}",
                    error_code="INVALID_TOKEN_RESPONSE",
                    status_code=200,
                )

    def get_access_token(self) -> str:
        """Get a valid access token for calling Traylinx Sentinel API endpoints.

        This method returns the current access token, automatically fetching a new one
        if the current token has expired. The access token is used for authenticating
        requests to Traylinx Sentinel API endpoints.

        Returns:
            str: A valid access token (JWT format)

        Raises:
            TokenExpiredError: If the token is unavailable after fetch attempt
            AuthenticationError: If token fetch fails due to invalid credentials
            NetworkError: If network issues prevent token fetch
            ValidationError: If client configuration is invalid

        Example:
            >>> client = TraylinxAuthClient()
            >>> token = client.get_access_token()
            >>> headers = {"Authorization": f"Bearer {token}"}
            >>> response = requests.get("https://auth.traylinx.com/a2a/rpc", headers=headers)

        Note:
            This method is thread-safe and handles automatic token refresh.
            The token is cached until expiration to minimize API calls.
        """
        if self._token_expiration < time.time():
            self._fetch_tokens()

        if not self._access_token:
            raise TokenExpiredError(
                "Access token is not available. Token fetch may have failed.",
                error_code="TOKEN_UNAVAILABLE",
                status_code=401,
            )

        return self._access_token

    def get_agent_secret_token(self) -> str:
        """Get a valid agent secret token for agent-to-agent communication.

        This method returns the current agent secret token, automatically fetching
        a new one if the current token has expired. The agent secret token is used
        for authenticating requests to other Traylinx agents.

        Returns:
            str: A valid agent secret token

        Raises:
            TokenExpiredError: If the token is unavailable after fetch attempt
            AuthenticationError: If token fetch fails due to invalid credentials
            NetworkError: If network issues prevent token fetch
            ValidationError: If client configuration is invalid

        Example:
            >>> client = TraylinxAuthClient()
            >>> token = client.get_agent_secret_token()
            >>> headers = {"X-Agent-Secret-Token": token, "X-Agent-User-Id": "agent-id"}
            >>> response = requests.post("https://other-agent.com/api", headers=headers)

        Note:
            This method is thread-safe and handles automatic token refresh.
            The token is cached until expiration to minimize API calls.
        """
        if self._token_expiration < time.time():
            self._fetch_tokens()

        if not self._agent_secret_token:
            raise TokenExpiredError(
                "Agent secret token is not available. Token fetch may have failed.",
                error_code="TOKEN_UNAVAILABLE",
                status_code=401,
            )

        return self._agent_secret_token

    def get_request_headers(self) -> Dict[str, str]:
        """Get headers for calling Traylinx Sentinel API endpoints.

        Returns headers that include both access_token and agent_secret_token,
        suitable for making requests to Traylinx Sentinel API endpoints that
        require full authentication context.

        Returns:
            Dict[str, str]: Headers dictionary containing:
                - Authorization: Bearer <access_token>
                - X-Agent-Secret-Token: <agent_secret_token>
                - X-Agent-User-Id: <agent_user_id>

        Raises:
            TokenExpiredError: If tokens are unavailable
            AuthenticationError: If token fetch fails
            NetworkError: If network issues occur during token fetch

        Example:
            >>> client = TraylinxAuthClient()
            >>> headers = client.get_request_headers()
            >>> response = requests.post(
            ...     "https://auth.traylinx.com/a2a/rpc",
            ...     headers=headers,
            ...     json={"jsonrpc": "2.0", "method": "health_check", "id": "1"}
            ... )

        Note:
            Use this method when calling Traylinx Sentinel API endpoints.
            For agent-to-agent communication, use get_agent_request_headers() instead.
        """
        headers = {
            "Authorization": f"Bearer {self.get_access_token()}",
            "X-Agent-Secret-Token": self.get_agent_secret_token(),
            "X-Agent-User-Id": self.agent_user_id,
        }
        return headers

    def get_agent_request_headers(self) -> Dict[str, str]:
        """Get headers for agent-to-agent communication.

        Returns headers that include ONLY the agent_secret_token (no access_token),
        suitable for making requests to other Traylinx agents. This follows the
        security principle of least privilege by not including unnecessary tokens.

        Returns:
            Dict[str, str]: Headers dictionary containing:
                - X-Agent-Secret-Token: <agent_secret_token>
                - X-Agent-User-Id: <agent_user_id>

        Raises:
            TokenExpiredError: If agent secret token is unavailable
            AuthenticationError: If token fetch fails
            NetworkError: If network issues occur during token fetch

        Example:
            >>> client = TraylinxAuthClient()
            >>> headers = client.get_agent_request_headers()
            >>> response = requests.post(
            ...     "https://other-agent.com/api/process",
            ...     headers=headers,
            ...     json={"data": ["item1", "item2"]}
            ... )

        Note:
            This is the recommended method for agent-to-agent communication.
            It does NOT include the access_token for security reasons.
        """
        headers = {
            "X-Agent-Secret-Token": self.get_agent_secret_token(),
            "X-Agent-User-Id": self.agent_user_id,
        }
        return headers

    def validate_token(self, agent_secret_token: str, agent_user_id: str) -> bool:
        """Validate an agent secret token against the Traylinx Sentinel API.

        This method validates whether a given agent secret token is valid and active
        by making a request to the Traylinx Sentinel token introspection endpoint.
        It's commonly used to validate incoming requests from other agents.

        Args:
            agent_secret_token (str): The agent secret token to validate
            agent_user_id (str): The agent user ID associated with the token

        Returns:
            bool: True if the token is valid and active, False otherwise

        Raises:
            AuthenticationError: If the validation request fails due to invalid
                access token or malformed response
            NetworkError: If network issues occur during validation
            ValidationError: If the response format is invalid

        Example:
            >>> client = TraylinxAuthClient()
            >>>
            >>> # Validate incoming request in FastAPI endpoint
            >>> @app.post("/protected")
            >>> async def protected_endpoint(request: Request):
            ...     token = request.headers.get("x-agent-secret-token")
            ...     agent_id = request.headers.get("x-agent-user-id")
            ...
            ...     if not client.validate_token(token, agent_id):
            ...         raise HTTPException(status_code=401, detail="Invalid token")
            ...
            ...     return {"message": "Token is valid"}

        Note:
            This method uses the client's access_token to authenticate the
            validation request to the Traylinx Sentinel API. The method is
            thread-safe and handles automatic token refresh if needed.
        """
        headers = {
            "Authorization": f"Bearer {self.get_access_token()}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "agent_secret_token": agent_secret_token,
            "agent_user_id": agent_user_id,
        }

        try:
            response = self._session.post(
                f"{self.api_base_url.rstrip('/')}/oauth/agent/introspect",
                headers=headers,
                data=data,
                timeout=self.config.timeout,
            )

            if response.status_code == 200:
                try:
                    return response.json().get("active", False)
                except (ValueError, TypeError) as e:
                    raise AuthenticationError(
                        f"Failed to parse token validation response: {str(e)}",
                        error_code="INVALID_VALIDATION_RESPONSE",
                        status_code=200,
                    )
            elif response.status_code == 401:
                # Invalid access token used for validation
                raise AuthenticationError(
                    "Access token invalid for token validation",
                    error_code="INVALID_ACCESS_TOKEN",
                    status_code=401,
                )
            else:
                # Other HTTP errors
                response.raise_for_status()

        except requests.exceptions.RequestException as e:
            self._handle_request_error(e, "token validation")

        return False

    def rpc_call(
        self,
        method: str,
        params: dict,
        rpc_url: str = None,
        include_agent_credentials: bool = None,
    ):
        rpc_url = rpc_url or f"{self.api_base_url.rstrip('/')}/a2a/rpc"

        # Auto-detect: if calling auth service (default), only use access_token
        # If calling another agent, use ONLY agent_secret_token (NO access_token!)
        if include_agent_credentials is None:
            include_agent_credentials = rpc_url != f"{self.api_base_url.rstrip('/')}/a2a/rpc"

        headers = {
            "Content-Type": "application/json",
        }

        if include_agent_credentials:
            # When calling other agents: use ONLY agent_secret_token
            headers["X-Agent-Secret-Token"] = self.get_agent_secret_token()
            headers["X-Agent-User-Id"] = self.agent_user_id
        else:
            # When calling auth service: use access_token
            headers["Authorization"] = f"Bearer {self.get_access_token()}"

        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": str(uuid.uuid4()),
        }

        try:
            response = self._session.post(
                rpc_url, headers=headers, json=payload, timeout=self.config.timeout
            )
            response.raise_for_status()

            try:
                result = response.json()

                # Check for JSON-RPC error response
                if "error" in result:
                    error_info = result["error"]
                    error_code = error_info.get("code", "RPC_ERROR")
                    error_message = error_info.get("message", "RPC call failed")

                    if error_code == -32600:  # Invalid Request
                        raise ValidationError(
                            f"Invalid RPC request: {error_message}",
                            error_code="INVALID_RPC_REQUEST",
                            status_code=400,
                        )
                    elif error_code == -32601:  # Method not found
                        raise ValidationError(
                            f"RPC method '{method}' not found: {error_message}",
                            error_code="METHOD_NOT_FOUND",
                            status_code=404,
                        )
                    elif error_code == -32602:  # Invalid params
                        raise ValidationError(
                            f"Invalid RPC parameters: {error_message}",
                            error_code="INVALID_RPC_PARAMS",
                            status_code=400,
                        )
                    else:
                        raise TraylinxAuthError(
                            f"RPC error ({error_code}): {error_message}",
                            error_code=str(error_code),
                            status_code=500,
                        )

                return result

            except (ValueError, TypeError) as e:
                raise TraylinxAuthError(
                    f"Failed to parse RPC response: {str(e)}",
                    error_code="INVALID_RPC_RESPONSE",
                    status_code=200,
                )

        except requests.exceptions.RequestException as e:
            self._handle_request_error(e, f"RPC call to {method}")

    def rpc_introspect_token(self, agent_secret_token: str, agent_user_id: str):
        params = {
            "agent_secret_token": agent_secret_token,
            "agent_user_id": agent_user_id,
        }
        return self.rpc_call("introspect_token", params)

    def rpc_get_capabilities(self):
        return self.rpc_call("get_capabilities", {})

    def rpc_health_check(self):
        return self.rpc_call("health_check", {})

    # A2A Extension Methods
    def get_a2a_headers(self) -> dict:
        """Get A2A-compatible authentication headers using Bearer token format.

        Returns headers in A2A-compliant format:
        - Authorization: Bearer {agent_secret_token}
        - X-Agent-User-Id: {agent_user_id}

        Returns:
            Dict with A2A-compatible authentication headers
        """
        return {
            "Authorization": f"Bearer {self.get_agent_secret_token()}",
            "X-Agent-User-Id": self.agent_user_id,
        }

    def validate_a2a_request(self, headers: dict) -> bool:
        """Validate A2A request supporting both Bearer tokens and custom headers.

        This method provides dual-mode validation:
        1. Bearer token format: Authorization: Bearer {token}
        2. Custom header format: X-Agent-Secret-Token: {token}

        Args:
            headers: Request headers dict (case-insensitive)

        Returns:
            True if authentication is valid, False otherwise
        """
        # Normalize headers to lowercase for case-insensitive lookup
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        # Try Bearer token format first (A2A standard)
        auth_header = normalized_headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.replace("Bearer ", "").strip()
            agent_id = normalized_headers.get("x-agent-user-id")
            if token and agent_id:
                return self.validate_token(token, agent_id)

        # Fall back to custom header format (backward compatibility)
        custom_token = normalized_headers.get("x-agent-secret-token")
        agent_id = normalized_headers.get("x-agent-user-id")
        if custom_token and agent_id:
            return self.validate_token(custom_token, agent_id)

        return False

    def detect_auth_mode(self, headers: dict) -> str:
        """Detect authentication mode from request headers.

        Args:
            headers: Request headers dict

        Returns:
            'bearer' for Bearer token format, 'custom' for custom headers, 'none' if no auth detected
        """
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        if normalized_headers.get("authorization", "").startswith("Bearer "):
            return "bearer"
        elif normalized_headers.get("x-agent-secret-token"):
            return "custom"
        else:
            return "none"

    # =========================================================================
    # Stargate P2P Identity Methods
    # =========================================================================

    def get_p2p_challenge(self, peer_id: str) -> str:
        """Fetch a cryptographically signed challenge from Sentinel.

        The challenge must be signed by the agent's private key and then
        sent back to Sentinel via `certify_p2p_identity`.

        Args:
            peer_id: The Stargate peer ID (32-character hex)

        Returns:
            The signed challenge string from Sentinel

        Raises:
            AuthenticationError: If access denied
            NetworkError: If network issues occur
        """
        headers = {
            "Authorization": f"Bearer {self.get_access_token()}",
            "Content-Type": "application/json",
        }

        try:
            response = self._session.get(
                f"{self.api_base_url.rstrip('/')}/a2a/p2p/challenge",
                params={"peer_id": peer_id},
                headers=headers,
                timeout=self.config.timeout,
            )
            response.raise_for_status()
            return response.json()["challenge"]
        except Exception as e:
            self._handle_request_error(e, "Failed to fetch P2P challenge")

    def certify_p2p_identity(
        self,
        peer_id: str,
        public_key: str,
        signature: str,
        challenge: str,
    ) -> Dict[str, Any]:
        """Request a P2P certificate from Sentinel for Stargate identity.

        This method certifies a Stargate P2P identity by sending a signed challenge
        to Sentinel. Upon successful verification, Sentinel issues a JWT certificate
        that can be used for P2P authentication.

        Args:
            peer_id: The Stargate peer ID (hex-encoded hash of public key)
            public_key: Ed25519 public key (base64-encoded)
            signature: Signature of the challenge (base64-encoded)
            challenge: The challenge string that was signed

        Returns:
            Dict containing:
                - certificate: JWT certificate string
                - expires_at: ISO 8601 expiration timestamp

        Raises:
            AuthenticationError: If signature verification fails or access denied
            NetworkError: If network issues prevent certification
            ValidationError: If parameters are invalid

        Example:
            >>> from traylinx_stargate.identity import IdentityManager
            >>> import base64
            >>>
            >>> identity = IdentityManager()
            >>> identity.generate_keypair()
            >>>
            >>> challenge = f"certify-{time.time()}"
            >>> signature = identity.sign_message(challenge.encode())
            >>>
            >>> client = TraylinxAuthClient()
            >>> result = client.certify_p2p_identity(
            ...     peer_id=identity.get_peer_id(),
            ...     public_key=identity.get_public_key_b64(),
            ...     signature=base64.b64encode(signature).decode(),
            ...     challenge=challenge,
            ... )
            >>> print(f"Certificate expires: {result['expires_at']}")

        Note:
            This method requires a valid access token. Call `get_access_token()` first
            or use the client in a context where tokens are automatically managed.
        """
        # Validate inputs
        if not peer_id or len(peer_id) != 32:
            raise ValidationError(
                "peer_id must be a 32-character hex string",
                error_code="INVALID_PEER_ID",
                status_code=400,
            )

        if not public_key:
            raise ValidationError(
                "public_key is required",
                error_code="MISSING_PUBLIC_KEY",
                status_code=400,
            )

        if not signature:
            raise ValidationError(
                "signature is required",
                error_code="MISSING_SIGNATURE",
                status_code=400,
            )

        if not challenge:
            raise ValidationError(
                "challenge is required",
                error_code="MISSING_CHALLENGE",
                status_code=400,
            )

        headers = {
            "Authorization": f"Bearer {self.get_access_token()}",
            "Content-Type": "application/json",
        }

        payload = {
            "peer_id": peer_id,
            "public_key": public_key,
            "signature": signature,
            "challenge": challenge,
        }

        try:
            response = self._session.post(
                f"{self.api_base_url.rstrip('/')}/a2a/p2p/certify",
                headers=headers,
                json=payload,
                timeout=self.config.timeout,
            )

            if response.status_code >= 200 and response.status_code < 300:
                try:
                    result = response.json()
                    if "certificate" not in result or "expires_at" not in result:
                        raise AuthenticationError(
                            "Invalid certification response: missing certificate or expires_at",
                            error_code="INVALID_CERT_RESPONSE",
                            status_code=response.status_code,
                        )
                    return result
                except (ValueError, TypeError) as e:
                    raise AuthenticationError(
                        f"Failed to parse certification response: {str(e)}",
                        error_code="INVALID_CERT_RESPONSE",
                        status_code=response.status_code,
                    )
            elif response.status_code == 401:
                raise AuthenticationError(
                    "Invalid cryptographic signature",
                    error_code="INVALID_SIGNATURE",
                    status_code=401,
                )
            elif response.status_code == 409:
                raise AuthenticationError(
                    "PeerID already claimed by another user",
                    error_code="PEER_ID_CLAIMED",
                    status_code=409,
                )
            else:
                response.raise_for_status()

        except requests.exceptions.RequestException as e:
            self._handle_request_error(e, "P2P certification")

        return {}

    def get_p2p_certificate_status(self, peer_id: str) -> Optional[Dict[str, Any]]:
        """Check the status of a P2P certificate.

        Args:
            peer_id: The Stargate peer ID to check

        Returns:
            Dict with certificate status, or None if not found

        Note:
            This is a placeholder for future implementation.
            Currently returns None.
        """
        # Placeholder for future implementation
        # Would call GET /a2a/p2p/status?peer_id=xxx
        return None
