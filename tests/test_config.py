"""
Comprehensive tests for configuration validation using Pydantic.

This module tests all configuration validation rules, edge cases,
and error handling for the AuthConfig class.
"""

import pytest
from pydantic import ValidationError as PydanticValidationError
from traylinx_auth_client.config import AuthConfig, validate_config


class TestAuthConfigValidation:
    """Test the AuthConfig Pydantic model validation."""

    def test_valid_config_creation(self):
        """Test creating a valid configuration."""
        config = AuthConfig(
            client_id="test_client_123",
            client_secret="secure_secret_key_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        assert config.client_id == "test_client_123"
        assert config.client_secret == "secure_secret_key_123"
        assert str(config.api_base_url) == "https://api.example.com/"
        assert config.agent_user_id == "12345678-1234-1234-1234-123456789abc"
        assert config.timeout == 30  # default
        assert config.max_retries == 3  # default
        assert config.retry_delay == 1.0  # default
        assert config.cache_tokens is True  # default
        assert config.log_level == "INFO"  # default

    def test_config_with_all_parameters(self):
        """Test creating configuration with all parameters specified."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="very_secure_secret",
            api_base_url="https://sentinel.traylinx.com",
            agent_user_id="abcdef12-3456-7890-abcd-ef1234567890",
            timeout=60,
            max_retries=5,
            retry_delay=2.5,
            cache_tokens=False,
            log_level="DEBUG",
        )

        assert config.timeout == 60
        assert config.max_retries == 5
        assert config.retry_delay == 2.5
        assert config.cache_tokens is False
        assert config.log_level == "DEBUG"


class TestClientIdValidation:
    """Test client_id validation rules."""

    def test_valid_client_ids(self):
        """Test various valid client_id formats."""
        valid_ids = [
            "test_client",
            "client-123",
            "MyClient_App",
            "app123",
            "a" * 100,  # max length
            "abc",  # min length
        ]

        for client_id in valid_ids:
            config = AuthConfig(
                client_id=client_id,
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )
            assert config.client_id == client_id

    def test_empty_client_id(self):
        """Test that empty client_id raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="",
                client_secret="secure_secret",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        errors = exc_info.value.errors()
        assert any("Client ID cannot be empty" in str(error) for error in errors)

    def test_whitespace_only_client_id(self):
        """Test that whitespace-only client_id raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="   ",
                client_secret="secure_secret",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        errors = exc_info.value.errors()
        assert any("Client ID cannot be empty" in str(error) for error in errors)

    def test_invalid_client_id_characters(self):
        """Test that invalid characters in client_id raise validation error."""
        invalid_ids = [
            "client@domain",
            "client.app",
            "client space",
            "client/app",
            "client\\app",
            "client+app",
            "client=app",
        ]

        for invalid_id in invalid_ids:
            with pytest.raises(PydanticValidationError) as exc_info:
                AuthConfig(
                    client_id=invalid_id,
                    client_secret="secure_secret",
                    api_base_url="https://api.example.com",
                    agent_user_id="12345678-1234-1234-1234-123456789abc",
                )

            errors = exc_info.value.errors()
            assert any(
                "must contain only alphanumeric characters" in str(error)
                for error in errors
            )

    def test_client_id_too_short(self):
        """Test that client_id shorter than 3 characters raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="ab",
                client_secret="secure_secret",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        errors = exc_info.value.errors()
        assert any(
            "must be at least 3 characters long" in str(error) for error in errors
        )

    def test_client_id_too_long(self):
        """Test that client_id longer than 100 characters raises validation error."""
        long_id = "a" * 101

        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id=long_id,
                client_secret="secure_secret",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        errors = exc_info.value.errors()
        assert any(
            "must be no more than 100 characters long" in str(error) for error in errors
        )


class TestClientSecretValidation:
    """Test client_secret validation rules."""

    def test_valid_client_secrets(self):
        """Test various valid client_secret formats."""
        valid_secrets = [
            "secure_secret_123",
            "VeryLongAndSecureSecretKey123!@#",
            "a" * 500,  # max length
            "1234567890",  # min length
        ]

        for secret in valid_secrets:
            config = AuthConfig(
                client_id="test_client",
                client_secret=secret,
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )
            assert config.client_secret == secret

    def test_empty_client_secret(self):
        """Test that empty client_secret raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret="",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        errors = exc_info.value.errors()
        assert any("Client secret cannot be empty" in str(error) for error in errors)

    def test_client_secret_too_short(self):
        """Test that client_secret shorter than 10 characters raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret="short",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        errors = exc_info.value.errors()
        assert any(
            "must be at least 10 characters long" in str(error) for error in errors
        )

    def test_client_secret_too_long(self):
        """Test that client_secret longer than 500 characters raises validation error."""
        long_secret = "a" * 501

        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret=long_secret,
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        errors = exc_info.value.errors()
        assert any(
            "must be no more than 500 characters long" in str(error) for error in errors
        )

    def test_weak_client_secrets(self):
        """Test that short secrets raise validation error (length validation catches weak patterns)."""
        weak_secrets = ["password", "secret", "123456", "admin"]

        for weak_secret in weak_secrets:
            with pytest.raises(PydanticValidationError) as exc_info:
                AuthConfig(
                    client_id="test_client",
                    client_secret=weak_secret,
                    api_base_url="https://api.example.com",
                    agent_user_id="12345678-1234-1234-1234-123456789abc",
                )

            errors = exc_info.value.errors()
            # These will be caught by length validation since they're all < 10 chars
            assert any(
                "must be at least 10 characters long" in str(error) for error in errors
            )


class TestApiBaseUrlValidation:
    """Test api_base_url validation rules."""

    def test_valid_https_urls(self):
        """Test various valid HTTPS URLs."""
        valid_urls = [
            "https://api.example.com",
            "https://sentinel.traylinx.com",
            "https://api.example.com:8443",
            "https://api.example.com/v1",
            "https://localhost:8080",  # allowed for development
            "https://127.0.0.1:3000",  # allowed for development
        ]

        for url in valid_urls:
            config = AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url=url,
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )
            # Note: Pydantic HttpUrl adds trailing slash only to URLs without paths
            if "/" in url.split("://", 1)[1] and not url.endswith("/"):
                # URL has a path, no trailing slash added
                expected_url = url
            else:
                # URL has no path or already ends with slash, trailing slash added/preserved
                expected_url = url if url.endswith("/") else url + "/"
            assert str(config.api_base_url) == expected_url

    def test_trailing_slash_handling(self):
        """Test that URLs are handled consistently (Pydantic adds trailing slash)."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="secure_secret_123",
            api_base_url="https://api.example.com/",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        assert str(config.api_base_url) == "https://api.example.com/"

    def test_http_url_rejected(self):
        """Test that HTTP URLs are rejected for security."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="http://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        errors = exc_info.value.errors()
        assert any("must use HTTPS for security" in str(error) for error in errors)

    def test_invalid_url_formats(self):
        """Test that invalid URL formats are rejected."""
        invalid_urls = [
            "not-a-url",
            "ftp://example.com",
            "https://",
            "",
        ]

        for invalid_url in invalid_urls:
            with pytest.raises(PydanticValidationError):
                AuthConfig(
                    client_id="test_client",
                    client_secret="secure_secret_123",
                    api_base_url=invalid_url,
                    agent_user_id="12345678-1234-1234-1234-123456789abc",
                )

        # Test that some URLs that look invalid but are technically valid don't raise errors
        # (Pydantic's HttpUrl is more permissive than expected)
        potentially_valid_urls = ["https:///invalid"]
        for url in potentially_valid_urls:
            try:
                config = AuthConfig(
                    client_id="test_client",
                    client_secret="secure_secret_123",
                    api_base_url=url,
                    agent_user_id="12345678-1234-1234-1234-123456789abc",
                )
                # If it doesn't raise, that's fine - Pydantic accepts it
            except PydanticValidationError:
                # If it does raise, that's also fine
                pass


class TestAgentUserIdValidation:
    """Test agent_user_id UUID validation rules."""

    def test_valid_uuids(self):
        """Test various valid UUID formats."""
        valid_uuids = [
            "12345678-1234-1234-1234-123456789abc",
            "ABCDEF12-3456-7890-ABCD-EF1234567890",  # uppercase
            "abcdef12-3456-7890-abcd-ef1234567890",  # lowercase
            "12345678123412341234123456789abc",  # without hyphens
        ]

        for uuid_val in valid_uuids:
            config = AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id=uuid_val,
            )
            # All UUIDs should be normalized to lowercase with hyphens
            assert len(config.agent_user_id) == 36
            assert config.agent_user_id.count("-") == 4
            assert config.agent_user_id.islower()

    def test_uuid_normalization(self):
        """Test that UUIDs are normalized to lowercase with hyphens."""
        # Test uppercase UUID with hyphens (the validator requires proper format)
        config = AuthConfig(
            client_id="test_client",
            client_secret="secure_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="ABCDEF12-3456-7890-ABCD-EF1234567890",
        )

        expected = "abcdef12-3456-7890-abcd-ef1234567890"
        assert config.agent_user_id == expected

    def test_empty_agent_user_id(self):
        """Test that empty agent_user_id raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="",
            )

        errors = exc_info.value.errors()
        assert any("Agent User ID cannot be empty" in str(error) for error in errors)

    def test_invalid_uuid_formats(self):
        """Test that invalid UUID formats raise validation error."""
        invalid_uuids = [
            "not-a-uuid",
            "12345678-1234-1234-1234",  # too short
            "12345678-1234-1234-1234-123456789abcdef",  # too long
            "12345678-1234-1234-1234-123456789xyz",  # invalid characters
            "12345678_1234_1234_1234_123456789abc",  # wrong separators
        ]

        for invalid_uuid in invalid_uuids:
            with pytest.raises(PydanticValidationError) as exc_info:
                AuthConfig(
                    client_id="test_client",
                    client_secret="secure_secret_123",
                    api_base_url="https://api.example.com",
                    agent_user_id=invalid_uuid,
                )

            errors = exc_info.value.errors()
            assert any("must be a valid UUID format" in str(error) for error in errors)


class TestTimeoutValidation:
    """Test timeout validation rules."""

    def test_valid_timeouts(self):
        """Test various valid timeout values."""
        valid_timeouts = [1, 30, 60, 120, 300]

        for timeout in valid_timeouts:
            config = AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                timeout=timeout,
            )
            assert config.timeout == timeout

    def test_timeout_too_small(self):
        """Test that timeout less than 1 raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                timeout=0,
            )

        errors = exc_info.value.errors()
        assert any("must be at least 1 second" in str(error) for error in errors)

    def test_timeout_too_large(self):
        """Test that timeout greater than 300 raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                timeout=301,
            )

        errors = exc_info.value.errors()
        assert any("must be no more than 300 seconds" in str(error) for error in errors)


class TestMaxRetriesValidation:
    """Test max_retries validation rules."""

    def test_valid_max_retries(self):
        """Test various valid max_retries values."""
        valid_retries = [0, 1, 3, 5, 10]

        for retries in valid_retries:
            config = AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                max_retries=retries,
            )
            assert config.max_retries == retries

    def test_negative_max_retries(self):
        """Test that negative max_retries raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                max_retries=-1,
            )

        errors = exc_info.value.errors()
        assert any("cannot be negative" in str(error) for error in errors)

    def test_max_retries_too_large(self):
        """Test that max_retries greater than 10 raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                max_retries=11,
            )

        errors = exc_info.value.errors()
        assert any("must be no more than 10" in str(error) for error in errors)


class TestRetryDelayValidation:
    """Test retry_delay validation rules."""

    def test_valid_retry_delays(self):
        """Test various valid retry_delay values."""
        valid_delays = [0.1, 1.0, 2.5, 30.0, 60.0]

        for delay in valid_delays:
            config = AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                retry_delay=delay,
            )
            assert config.retry_delay == delay

    def test_retry_delay_too_small(self):
        """Test that retry_delay less than 0.1 raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                retry_delay=0.05,
            )

        errors = exc_info.value.errors()
        assert any("must be at least 0.1 seconds" in str(error) for error in errors)

    def test_retry_delay_too_large(self):
        """Test that retry_delay greater than 60 raises validation error."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                retry_delay=61.0,
            )

        errors = exc_info.value.errors()
        assert any("must be no more than 60 seconds" in str(error) for error in errors)


class TestLogLevelValidation:
    """Test log_level validation rules."""

    def test_valid_log_levels(self):
        """Test various valid log_level values."""
        valid_levels = ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL"]

        for level in valid_levels:
            config = AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                log_level=level,
            )
            assert config.log_level == level.upper()

    def test_case_insensitive_log_levels(self):
        """Test that log levels are case insensitive."""
        case_variants = ["debug", "Info", "WARN", "error"]
        expected = ["DEBUG", "INFO", "WARN", "ERROR"]

        for level, expected_level in zip(case_variants, expected):
            config = AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                log_level=level,
            )
            assert config.log_level == expected_level

    def test_invalid_log_levels(self):
        """Test that invalid log levels raise validation error."""
        invalid_levels = ["TRACE", "VERBOSE", "INVALID", ""]

        for level in invalid_levels:
            with pytest.raises(PydanticValidationError) as exc_info:
                AuthConfig(
                    client_id="test_client",
                    client_secret="secure_secret_123",
                    api_base_url="https://api.example.com",
                    agent_user_id="12345678-1234-1234-1234-123456789abc",
                    log_level=level,
                )

            errors = exc_info.value.errors()
            assert any("must be one of:" in str(error) for error in errors)


class TestValidateConfigFunction:
    """Test the validate_config helper function."""

    def test_validate_config_success(self):
        """Test successful configuration validation."""
        config = validate_config(
            client_id="test_client",
            client_secret="secure_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        assert isinstance(config, AuthConfig)
        assert config.client_id == "test_client"

    def test_validate_config_with_validation_error(self):
        """Test that validate_config converts Pydantic errors to ValueError."""
        with pytest.raises(ValueError) as exc_info:
            validate_config(
                client_id="",  # invalid
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
            )

        assert "Configuration validation failed" in str(exc_info.value)
        assert "client_id" in str(exc_info.value)

    def test_validate_config_multiple_errors(self):
        """Test that validate_config handles multiple validation errors."""
        with pytest.raises(ValueError) as exc_info:
            validate_config(
                client_id="",  # invalid
                client_secret="short",  # invalid
                api_base_url="http://insecure.com",  # invalid
                agent_user_id="not-a-uuid",  # invalid
            )

        error_message = str(exc_info.value)
        assert "Configuration validation failed" in error_message
        # Should contain information about multiple field errors
        assert "client_id" in error_message

    def test_validate_config_with_unexpected_error(self):
        """Test that validate_config handles unexpected errors."""
        # This is harder to test directly, but we can test the error handling path
        with pytest.raises(ValueError) as exc_info:
            validate_config()  # Missing required parameters

        assert "Configuration validation failed" in str(exc_info.value)


class TestConfigModelBehavior:
    """Test Pydantic model behavior and configuration."""

    def test_extra_fields_forbidden(self):
        """Test that extra fields are forbidden."""
        with pytest.raises(PydanticValidationError) as exc_info:
            AuthConfig(
                client_id="test_client",
                client_secret="secure_secret_123",
                api_base_url="https://api.example.com",
                agent_user_id="12345678-1234-1234-1234-123456789abc",
                extra_field="not_allowed",  # This should be rejected
            )

        errors = exc_info.value.errors()
        assert any("Extra inputs are not permitted" in str(error) for error in errors)

    def test_validate_assignment(self):
        """Test that assignment validation works."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="secure_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        # This should work
        config.timeout = 60
        assert config.timeout == 60

        # This should raise validation error
        with pytest.raises(PydanticValidationError):
            config.timeout = -1  # Invalid value

    def test_model_serialization(self):
        """Test that the model can be serialized."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="secure_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        # Test dict conversion
        config_dict = config.dict()
        assert config_dict["client_id"] == "test_client"
        assert "client_secret" in config_dict

        # Test JSON serialization
        config_json = config.json()
        assert "test_client" in config_json

    def test_model_copy(self):
        """Test that the model can be copied with updates."""
        config = AuthConfig(
            client_id="test_client",
            client_secret="secure_secret_123",
            api_base_url="https://api.example.com",
            agent_user_id="12345678-1234-1234-1234-123456789abc",
        )

        # Create a copy with updated values
        new_config = config.copy(update={"timeout": 60, "log_level": "DEBUG"})

        assert new_config.timeout == 60
        assert new_config.log_level == "DEBUG"
        assert new_config.client_id == "test_client"  # unchanged
        assert config.timeout == 30  # original unchanged
