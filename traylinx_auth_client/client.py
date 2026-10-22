import os
import requests
import time
from threading import Lock
import uuid
from .security import destination, credential, credentials_from, token_state, valid_introspection, AUTH_RESPONSE
from .transport import SecureSession
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
        agent_token_ttl_seconds=None,
        refresh_skew_seconds=30,
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
            "agent_token_ttl_seconds": agent_token_ttl_seconds,
            "refresh_skew_seconds": refresh_skew_seconds,
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
            ) from None

        # Set instance attributes from validated config
        self.client_id = self.config.client_id
        self.client_secret = self.config.client_secret
        self.api_base_url = str(self.config.api_base_url)
        self.agent_user_id = self.config.agent_user_id

        self._access_token = None
        self._agent_secret_token = None
        self._token_expiration = 0
        self._agent_token_expiration = 0
        self._generation = 0
        self._last_refresh_error = None
        self._lock = Lock()

        # Initialize session with retry configuration
        self._session = self._create_session_with_retries()

    def _create_session_with_retries(self) -> requests.Session:
        return SecureSession(self.config.timeout, self.config.max_retries, self.config.retry_delay)

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
            ) from None
        elif isinstance(error, requests.exceptions.ConnectionError):
            raise NetworkError(
                f"Connection failed during {context}. Check network connectivity and API URL.",
                error_code="CONNECTION_ERROR",
                status_code=0,
            ) from None
        elif isinstance(error, requests.exceptions.HTTPError):
            response = error.response
            status_code = response.status_code

            if status_code == 401:
                raise AuthenticationError(
                    f"Authentication failed during {context}. Check client credentials.",
                    error_code="INVALID_CREDENTIALS",
                    status_code=401,
                ) from None
            elif status_code == 429:
                raise NetworkError(
                    f"Rate limit exceeded during {context}. Please retry after some time.",
                    error_code="RATE_LIMIT",
                    status_code=429,
                ) from None
            elif 500 <= status_code < 600:
                raise NetworkError(
                    f"Server error ({status_code}) during {context}. The service may be temporarily unavailable.",
                    error_code="SERVER_ERROR",
                    status_code=status_code,
                ) from None
            else:
                raise NetworkError(
                    f"HTTP error ({status_code}) during {context}",
                    error_code="HTTP_ERROR",
                    status_code=status_code,
                ) from None
        else:
            raise TraylinxAuthError(
                f"Unexpected error during {context}",
                error_code="UNKNOWN_ERROR",
            ) from None

    def _fetch_tokens(self, kind="access", generation=None):
        if generation is None:
            generation = self._generation
        with self._lock:
            expiry = self._agent_token_expiration if kind == "agent" else self._token_expiration
            token = self._agent_secret_token if kind == "agent" else self._access_token
            if self._generation != generation:
                if self._last_refresh_error is not None:
                    kind, message, code, status = self._last_refresh_error
                    raise kind(message, error_code=code, status_code=status) from None
                return self._access_token, self._agent_secret_token
            if token and self.config.cache_tokens and expiry > time.time():
                return self._access_token, self._agent_secret_token
            started = time.time()
            try:
                destination(self.api_base_url, base=True)
                response = self._session.post(f"{self.api_base_url.rstrip('/')}/oauth/token",
                    data={"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret, "scope": "a2a"},
                    timeout=self.config.timeout, response_limit=AUTH_RESPONSE)
                response.raise_for_status()
                values = token_state(response.json(), started, self.config.agent_token_ttl_seconds, self.config.refresh_skew_seconds)
                self._access_token, self._agent_secret_token, self._token_expiration, self._agent_token_expiration = values
                self._generation += 1
                self._last_refresh_error = None
                return self._access_token, self._agent_secret_token
            except Exception as error:
                self._access_token = self._agent_secret_token = None
                self._token_expiration = self._agent_token_expiration = 0
                self._generation += 1
                if isinstance(error, TraylinxAuthError):
                    safe_error = error
                elif isinstance(error, (ValueError, TypeError, KeyError)):
                    safe_error = AuthenticationError("Invalid token response", error_code="INVALID_TOKEN_RESPONSE")
                else:
                    try:
                        self._handle_request_error(error, "token fetch")
                    except TraylinxAuthError as converted:
                        safe_error = converted
                # Store only sanitized data, never transport objects or tracebacks.
                self._last_refresh_error = (type(safe_error), str(safe_error), safe_error.error_code, safe_error.status_code)
                raise safe_error from None

    def get_access_token(self) -> str:
        generation = self._generation
        with self._lock:
            if self.config.cache_tokens and self._access_token and self._token_expiration > time.time():
                return self._access_token
        return self._fetch_tokens("access", generation)[0]

    def get_agent_secret_token(self) -> str:
        generation = self._generation
        with self._lock:
            if self.config.cache_tokens and self._agent_secret_token and self._agent_token_expiration > time.time():
                return self._agent_secret_token
        return self._fetch_tokens("agent", generation)[1]

    def get_request_headers(self) -> Dict[str, str]:
        access, agent = self._fetch_tokens("agent")
        return {"Authorization": f"Bearer {access}", "X-Agent-Secret-Token": agent, "X-Agent-User-Id": self.agent_user_id}

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
        return self.introspect_token(agent_secret_token, agent_user_id)["active"]

    def introspect_token(self, agent_secret_token: str, agent_user_id: str) -> dict:
        if not credential(agent_secret_token) or not credential(agent_user_id) or len(agent_user_id) > 256:
            return {"active": False}
        try:
            response = self._session.post(f"{self.api_base_url.rstrip('/')}/oauth/agent/introspect",
                headers={"Authorization": f"Bearer {self.get_access_token()}", "Content-Type": "application/x-www-form-urlencoded"},
                data={"agent_secret_token": agent_secret_token, "agent_user_id": agent_user_id},
                timeout=self.config.timeout, response_limit=AUTH_RESPONSE)
            if response.status_code == 400:
                return {"active": False}
            response.raise_for_status()
            data = response.json()
            if not valid_introspection(data, agent_user_id):
                return {"active": False}
            return {key: data[key] for key in ("active", "agent_id", "scopes", "expires_at", "agent_type") if key in data}
        except requests.exceptions.RequestException as error:
            self._handle_request_error(error, "token validation")
        except (ValueError, TypeError):
            raise AuthenticationError("Invalid introspection response", error_code="INVALID_VALIDATION_RESPONSE") from None

    def rpc_call(
        self,
        method: str,
        params: dict,
        rpc_url: str = None,
        include_agent_credentials: bool = None,
    ):
        rpc_url = rpc_url or f"{self.api_base_url.rstrip('/')}/a2a/rpc"
        target = destination(rpc_url)
        sentinel = destination(self.api_base_url)
        if include_agent_credentials is False and (target.hostname, target.port or 443) != (sentinel.hostname, sentinel.port or 443):
            raise ValidationError("Access token may only be sent to Sentinel", error_code="UNSAFE_DESTINATION")

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
                if not isinstance(result, dict) or ("error" in result and not isinstance(result["error"], dict)):
                    raise ValueError("Invalid RPC envelope")

                # Check for JSON-RPC error response
                if "error" in result:
                    error_info = result["error"]
                    error_code = error_info.get("code", "RPC_ERROR")
                    error_message = "RPC call failed"

                    if error_code == -32600:  # Invalid Request
                        raise ValidationError(
                            f"Invalid RPC request: {error_message}",
                            error_code="INVALID_RPC_REQUEST",
                            status_code=400,
                        )
                    elif error_code == -32601:  # Method not found
                        raise ValidationError(
                            f"RPC method not found: {error_message}",
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
                            error_message,
                            error_code="RPC_ERROR",
                            status_code=500,
                        )

                return result

            except (ValueError, TypeError) as e:
                raise TraylinxAuthError(
                    "Invalid service response",
                    error_code="INVALID_RPC_RESPONSE",
                    status_code=200,
                )

        except requests.exceptions.RequestException as e:
            self._handle_request_error(e, "RPC call")

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
        auth = credentials_from(headers)
        return self.validate_token(auth[0], auth[1]) if auth else False

    def detect_auth_mode(self, headers: dict) -> str:
        auth = credentials_from(headers)
        return auth[2] if auth else "none"

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
                        "Invalid service response",
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
