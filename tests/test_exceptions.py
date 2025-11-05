"""
Comprehensive tests for the exception hierarchy and error handling.

This module tests all custom exceptions, their inheritance, attributes,
and proper error handling throughout the library.
"""

import pytest
from traylinx_auth_client.exceptions import (
    TraylinxAuthError,
    AuthenticationError,
    TokenExpiredError,
    NetworkError,
    ValidationError,
)


class TestTraylinxAuthError:
    """Test the base TraylinxAuthError class."""

    def test_base_exception_creation(self):
        """Test basic exception creation with message only."""
        error = TraylinxAuthError("Test error message")

        assert str(error) == "Test error message"
        assert error.error_code is None
        assert error.status_code is None

    def test_base_exception_with_error_code(self):
        """Test exception creation with error code."""
        error = TraylinxAuthError("Test error", error_code="TEST_ERROR")

        assert str(error) == "Test error"
        assert error.error_code == "TEST_ERROR"
        assert error.status_code is None

    def test_base_exception_with_status_code(self):
        """Test exception creation with status code."""
        error = TraylinxAuthError("Test error", status_code=500)

        assert str(error) == "Test error"
        assert error.error_code is None
        assert error.status_code == 500

    def test_base_exception_with_all_attributes(self):
        """Test exception creation with all attributes."""
        error = TraylinxAuthError(
            "Test error", error_code="TEST_ERROR", status_code=500
        )

        assert str(error) == "Test error"
        assert error.error_code == "TEST_ERROR"
        assert error.status_code == 500

    def test_base_exception_inheritance(self):
        """Test that TraylinxAuthError inherits from Exception."""
        error = TraylinxAuthError("Test error")

        assert isinstance(error, Exception)
        assert isinstance(error, TraylinxAuthError)


class TestAuthenticationError:
    """Test the AuthenticationError class."""

    def test_default_authentication_error(self):
        """Test default AuthenticationError creation."""
        error = AuthenticationError()

        assert str(error) == "Authentication failed"
        assert error.error_code == "AUTH_ERROR"
        assert error.status_code == 401

    def test_custom_authentication_error(self):
        """Test AuthenticationError with custom message."""
        error = AuthenticationError("Invalid credentials provided")

        assert str(error) == "Invalid credentials provided"
        assert error.error_code == "AUTH_ERROR"
        assert error.status_code == 401

    def test_authentication_error_inheritance(self):
        """Test AuthenticationError inheritance."""
        error = AuthenticationError()

        assert isinstance(error, TraylinxAuthError)
        assert isinstance(error, AuthenticationError)
        assert isinstance(error, Exception)

    def test_authentication_error_with_custom_attributes(self):
        """Test AuthenticationError with custom error code and status."""
        error = AuthenticationError(
            "Custom auth error", error_code="CUSTOM_AUTH", status_code=403
        )

        assert str(error) == "Custom auth error"
        assert error.error_code == "CUSTOM_AUTH"
        assert error.status_code == 403


class TestTokenExpiredError:
    """Test the TokenExpiredError class."""

    def test_default_token_expired_error(self):
        """Test default TokenExpiredError creation."""
        error = TokenExpiredError()

        assert str(error) == "Token has expired"
        assert error.error_code == "TOKEN_EXPIRED"
        assert error.status_code == 401

    def test_custom_token_expired_error(self):
        """Test TokenExpiredError with custom message."""
        error = TokenExpiredError("Access token expired at 2023-01-01")

        assert str(error) == "Access token expired at 2023-01-01"
        assert error.error_code == "TOKEN_EXPIRED"
        assert error.status_code == 401

    def test_token_expired_error_inheritance(self):
        """Test TokenExpiredError inheritance."""
        error = TokenExpiredError()

        assert isinstance(error, TraylinxAuthError)
        assert isinstance(error, TokenExpiredError)
        assert isinstance(error, Exception)


class TestNetworkError:
    """Test the NetworkError class."""

    def test_network_error_creation(self):
        """Test NetworkError creation with message."""
        error = NetworkError("Connection timeout")

        assert str(error) == "Connection timeout"
        assert error.error_code == "NETWORK_ERROR"
        assert error.status_code is None

    def test_network_error_with_status_code(self):
        """Test NetworkError with status code."""
        error = NetworkError("Server error", status_code=500)

        assert str(error) == "Server error"
        assert error.error_code == "NETWORK_ERROR"
        assert error.status_code == 500

    def test_network_error_with_custom_code(self):
        """Test NetworkError with custom error code."""
        error = NetworkError(
            "Rate limit exceeded", error_code="RATE_LIMIT", status_code=429
        )

        assert str(error) == "Rate limit exceeded"
        assert error.error_code == "RATE_LIMIT"
        assert error.status_code == 429

    def test_network_error_inheritance(self):
        """Test NetworkError inheritance."""
        error = NetworkError("Network issue")

        assert isinstance(error, TraylinxAuthError)
        assert isinstance(error, NetworkError)
        assert isinstance(error, Exception)


class TestValidationError:
    """Test the ValidationError class."""

    def test_validation_error_creation(self):
        """Test ValidationError creation with message."""
        error = ValidationError("Invalid client_id format")

        assert str(error) == "Invalid client_id format"
        assert error.error_code == "VALIDATION_ERROR"
        assert error.status_code == 400

    def test_validation_error_with_custom_attributes(self):
        """Test ValidationError with custom attributes."""
        error = ValidationError(
            "Invalid UUID format", error_code="INVALID_UUID", status_code=422
        )

        assert str(error) == "Invalid UUID format"
        assert error.error_code == "INVALID_UUID"
        assert error.status_code == 422

    def test_validation_error_inheritance(self):
        """Test ValidationError inheritance."""
        error = ValidationError("Validation failed")

        assert isinstance(error, TraylinxAuthError)
        assert isinstance(error, ValidationError)
        assert isinstance(error, Exception)


class TestExceptionHierarchy:
    """Test the overall exception hierarchy and relationships."""

    def test_all_exceptions_inherit_from_base(self):
        """Test that all custom exceptions inherit from TraylinxAuthError."""
        exceptions = [
            AuthenticationError(),
            TokenExpiredError(),
            NetworkError("test"),
            ValidationError("test"),
        ]

        for exc in exceptions:
            assert isinstance(exc, TraylinxAuthError)
            assert isinstance(exc, Exception)

    def test_exception_catching_hierarchy(self):
        """Test that exceptions can be caught at different levels."""
        # Test catching specific exception
        with pytest.raises(AuthenticationError):
            raise AuthenticationError("Auth failed")

        # Test catching base exception
        with pytest.raises(TraylinxAuthError):
            raise AuthenticationError("Auth failed")

        # Test catching generic Exception
        with pytest.raises(Exception):
            raise AuthenticationError("Auth failed")

    def test_exception_attributes_preserved(self):
        """Test that exception attributes are preserved through inheritance."""
        error = AuthenticationError("Custom message")

        # Catch as base class and verify attributes are preserved
        try:
            raise error
        except TraylinxAuthError as caught:
            assert str(caught) == "Custom message"
            assert caught.error_code == "AUTH_ERROR"
            assert caught.status_code == 401

    def test_multiple_exception_types(self):
        """Test handling multiple exception types."""

        def raise_different_errors(error_type):
            if error_type == "auth":
                raise AuthenticationError("Auth error")
            elif error_type == "network":
                raise NetworkError("Network error")
            elif error_type == "validation":
                raise ValidationError("Validation error")
            elif error_type == "token":
                raise TokenExpiredError("Token error")

        # Test each exception type
        with pytest.raises(AuthenticationError):
            raise_different_errors("auth")

        with pytest.raises(NetworkError):
            raise_different_errors("network")

        with pytest.raises(ValidationError):
            raise_different_errors("validation")

        with pytest.raises(TokenExpiredError):
            raise_different_errors("token")


class TestExceptionErrorCodes:
    """Test error codes and status codes for different scenarios."""

    def test_default_error_codes(self):
        """Test that default error codes are set correctly."""
        auth_error = AuthenticationError()
        assert auth_error.error_code == "AUTH_ERROR"

        token_error = TokenExpiredError()
        assert token_error.error_code == "TOKEN_EXPIRED"

        network_error = NetworkError("test")
        assert network_error.error_code == "NETWORK_ERROR"

        validation_error = ValidationError("test")
        assert validation_error.error_code == "VALIDATION_ERROR"

    def test_default_status_codes(self):
        """Test that default status codes are set correctly."""
        auth_error = AuthenticationError()
        assert auth_error.status_code == 401

        token_error = TokenExpiredError()
        assert token_error.status_code == 401

        network_error = NetworkError("test")
        assert network_error.status_code is None

        validation_error = ValidationError("test")
        assert validation_error.status_code == 400

    def test_custom_error_codes_override_defaults(self):
        """Test that custom error codes override defaults."""
        auth_error = AuthenticationError(
            "Custom auth error", error_code="CUSTOM_AUTH_ERROR", status_code=403
        )

        assert auth_error.error_code == "CUSTOM_AUTH_ERROR"
        assert auth_error.status_code == 403

    def test_error_code_consistency(self):
        """Test that error codes are consistent across instances."""
        error1 = AuthenticationError("Error 1")
        error2 = AuthenticationError("Error 2")

        assert error1.error_code == error2.error_code
        assert error1.status_code == error2.status_code


class TestExceptionStringRepresentation:
    """Test string representation and formatting of exceptions."""

    def test_exception_str_representation(self):
        """Test string representation of exceptions."""
        error = AuthenticationError("Authentication failed")
        assert str(error) == "Authentication failed"

    def test_exception_repr_representation(self):
        """Test repr representation of exceptions."""
        error = AuthenticationError("Auth failed")
        repr_str = repr(error)

        assert "AuthenticationError" in repr_str
        assert "Auth failed" in repr_str

    def test_empty_message_handling(self):
        """Test handling of empty or None messages."""
        # Test with empty string
        error1 = TraylinxAuthError("")
        assert str(error1) == ""

        # Test with None (should not happen in normal usage but test robustness)
        try:
            error2 = TraylinxAuthError(None)
            str(error2)  # Should not raise
        except TypeError:
            # This is acceptable behavior for None message
            pass

    def test_unicode_message_handling(self):
        """Test handling of unicode characters in error messages."""
        unicode_message = "Authentication failed: 用户认证失败"
        error = AuthenticationError(unicode_message)

        assert str(error) == unicode_message
        assert unicode_message in repr(error)


class TestExceptionUsagePatterns:
    """Test common usage patterns and edge cases."""

    def test_exception_chaining(self):
        """Test exception chaining with 'from' clause."""
        original_error = ValueError("Original error")

        try:
            raise original_error
        except ValueError as e:
            try:
                raise AuthenticationError("Auth failed") from e
            except AuthenticationError as chained_error:
                assert chained_error.__cause__ is original_error

    def test_exception_context_preservation(self):
        """Test that exception context is preserved."""

        def inner_function():
            raise ValueError("Inner error")

        def outer_function():
            try:
                inner_function()
            except ValueError:
                raise AuthenticationError("Outer error")

        with pytest.raises(AuthenticationError) as exc_info:
            outer_function()

        # Check that the context is preserved
        assert exc_info.value.__context__ is not None
        assert isinstance(exc_info.value.__context__, ValueError)

    def test_exception_with_additional_attributes(self):
        """Test adding additional attributes to exceptions."""
        error = NetworkError("Connection failed")
        error.retry_count = 3
        error.last_attempt = "2023-01-01T12:00:00Z"

        assert error.retry_count == 3
        assert error.last_attempt == "2023-01-01T12:00:00Z"
        assert error.error_code == "NETWORK_ERROR"

    def test_exception_equality(self):
        """Test exception equality comparison."""
        error1 = AuthenticationError("Auth failed")
        error2 = AuthenticationError("Auth failed")
        error3 = AuthenticationError("Different message")

        # Exceptions are not equal even with same message (default behavior)
        assert error1 is not error2
        assert error1 != error2  # Default Exception behavior

        # But they have the same type and attributes
        assert type(error1) == type(error2)
        assert error1.error_code == error2.error_code
        assert error1.status_code == error2.status_code
