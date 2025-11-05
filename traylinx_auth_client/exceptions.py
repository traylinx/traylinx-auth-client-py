"""
Custom exception hierarchy for TraylinxAuthClient.

This module defines a comprehensive exception hierarchy for handling
various error conditions in the TraylinxAuthClient library.
"""

from typing import Optional


class TraylinxAuthError(Exception):
    """Base exception for all TraylinxAuthClient errors.

    All exceptions raised by the TraylinxAuthClient library inherit from this base class.
    This allows for easy catching of all library-specific errors.

    Attributes:
        error_code: A string identifier for the specific error type
        status_code: HTTP status code associated with the error (if applicable)
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        status_code: Optional[int] = None,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.status_code = status_code


class AuthenticationError(TraylinxAuthError):
    """Raised when authentication fails.

    This includes invalid credentials, malformed responses from the auth service,
    or other authentication-related failures.
    """

    def __init__(
        self,
        message: str = "Authentication failed",
        error_code: str = "AUTH_ERROR",
        status_code: int = 401,
    ):
        super().__init__(message, error_code, status_code)


class TokenExpiredError(TraylinxAuthError):
    """Raised when a token has expired and cannot be refreshed.

    This is a specific type of authentication error that occurs when
    tokens expire and automatic refresh fails.
    """

    def __init__(
        self,
        message: str = "Token has expired",
        error_code: str = "TOKEN_EXPIRED",
        status_code: int = 401,
    ):
        super().__init__(message, error_code, status_code)


class NetworkError(TraylinxAuthError):
    """Raised when network communication fails.

    This includes timeouts, connection failures, DNS resolution errors,
    rate limiting, and server errors.
    """

    def __init__(
        self,
        message: str,
        error_code: str = "NETWORK_ERROR",
        status_code: Optional[int] = None,
    ):
        super().__init__(message, error_code, status_code)


class ValidationError(TraylinxAuthError):
    """Raised when input validation fails.

    This includes invalid configuration parameters, malformed URLs,
    invalid UUIDs, and other input validation failures.
    """

    def __init__(
        self, message: str, error_code: str = "VALIDATION_ERROR", status_code: int = 400
    ):
        super().__init__(message, error_code, status_code)
