"""Configuration and validation module for TraylinxAuthClient."""

import re
from typing import Optional
from pydantic import (
    BaseModel,
    validator,
    HttpUrl,
    ValidationError as PydanticValidationError,
)


class AuthConfig(BaseModel):
    """Configuration model with comprehensive validation for TraylinxAuthClient.

    This class provides input validation for all configuration parameters
    to ensure security and prevent runtime errors.
    """

    client_id: str
    client_secret: str
    api_base_url: HttpUrl
    agent_user_id: str
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    cache_tokens: bool = True
    log_level: str = "INFO"

    class Config:
        """Pydantic configuration."""

        validate_assignment = True
        extra = "forbid"  # Prevent extra fields

    @validator("client_id")
    def validate_client_id(cls, v):
        """Validate client_id format.

        Args:
            v: The client_id value to validate

        Returns:
            The validated client_id

        Raises:
            ValueError: If client_id format is invalid
        """
        if not v or not v.strip():
            raise ValueError("Client ID cannot be empty")

        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError(
                "Client ID must contain only alphanumeric characters, hyphens, and underscores. "
                f"Invalid characters found in: {v}"
            )

        if len(v) < 3:
            raise ValueError("Client ID must be at least 3 characters long")

        if len(v) > 100:
            raise ValueError("Client ID must be no more than 100 characters long")

        return v

    @validator("client_secret")
    def validate_client_secret(cls, v):
        """Validate client_secret security requirements.

        Args:
            v: The client_secret value to validate

        Returns:
            The validated client_secret

        Raises:
            ValueError: If client_secret doesn't meet security requirements
        """
        if not v or not v.strip():
            raise ValueError("Client secret cannot be empty")

        if len(v) < 10:
            raise ValueError(
                "Client secret must be at least 10 characters long for security. "
                f"Current length: {len(v)}"
            )

        if len(v) > 500:
            raise ValueError("Client secret must be no more than 500 characters long")

        # Check for common weak patterns
        if v.lower() in ["password", "secret", "123456", "admin"]:
            raise ValueError("Client secret appears to be a common weak value")

        return v

    @validator("api_base_url")
    def validate_api_base_url(cls, v):
        """Validate API base URL format and security.

        Args:
            v: The api_base_url value to validate

        Returns:
            The validated api_base_url

        Raises:
            ValueError: If URL format is invalid or insecure
        """
        url_str = str(v)

        # Ensure HTTPS for security
        if not url_str.startswith("https://"):
            raise ValueError(
                "API base URL must use HTTPS for security. " f"Received: {url_str}"
            )

        # Prevent localhost/internal URLs in production
        if any(
            host in url_str.lower() for host in ["localhost", "127.0.0.1", "0.0.0.0"]
        ):
            # Allow for development/testing
            pass

        # Remove trailing slash for consistency
        if url_str.endswith("/"):
            v = HttpUrl(url_str.rstrip("/"))

        return v

    @validator("agent_user_id")
    def validate_agent_user_id(cls, v):
        """Validate agent_user_id UUID format.

        Args:
            v: The agent_user_id value to validate

        Returns:
            The validated agent_user_id

        Raises:
            ValueError: If agent_user_id is not a valid UUID
        """
        if not v or not v.strip():
            raise ValueError("Agent User ID cannot be empty")

        # UUID v4 pattern (with or without hyphens)
        uuid_pattern = (
            r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$"
        )

        if not re.match(uuid_pattern, v.lower()):
            raise ValueError(
                "Agent User ID must be a valid UUID format (e.g., 12345678-1234-1234-1234-123456789abc). "
                f"Received: {v}"
            )

        # Normalize to lowercase with hyphens
        clean_uuid = v.lower().replace("-", "")
        formatted_uuid = f"{clean_uuid[:8]}-{clean_uuid[8:12]}-{clean_uuid[12:16]}-{clean_uuid[16:20]}-{clean_uuid[20:]}"

        return formatted_uuid

    @validator("timeout")
    def validate_timeout(cls, v):
        """Validate timeout value.

        Args:
            v: The timeout value to validate

        Returns:
            The validated timeout

        Raises:
            ValueError: If timeout is out of acceptable range
        """
        if v < 1:
            raise ValueError("Timeout must be at least 1 second")

        if v > 300:  # 5 minutes max
            raise ValueError("Timeout must be no more than 300 seconds (5 minutes)")

        return v

    @validator("max_retries")
    def validate_max_retries(cls, v):
        """Validate max_retries value.

        Args:
            v: The max_retries value to validate

        Returns:
            The validated max_retries

        Raises:
            ValueError: If max_retries is out of acceptable range
        """
        if v < 0:
            raise ValueError("Max retries cannot be negative")

        if v > 10:
            raise ValueError(
                "Max retries must be no more than 10 to prevent excessive delays"
            )

        return v

    @validator("retry_delay")
    def validate_retry_delay(cls, v):
        """Validate retry_delay value.

        Args:
            v: The retry_delay value to validate

        Returns:
            The validated retry_delay

        Raises:
            ValueError: If retry_delay is out of acceptable range
        """
        if v < 0.1:
            raise ValueError("Retry delay must be at least 0.1 seconds")

        if v > 60:
            raise ValueError("Retry delay must be no more than 60 seconds")

        return v

    @validator("log_level")
    def validate_log_level(cls, v):
        """Validate log_level value.

        Args:
            v: The log_level value to validate

        Returns:
            The validated log_level

        Raises:
            ValueError: If log_level is not a valid level
        """
        valid_levels = ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL"]

        if v.upper() not in valid_levels:
            raise ValueError(
                f'Log level must be one of: {", ".join(valid_levels)}. '
                f"Received: {v}"
            )

        return v.upper()


def validate_config(**kwargs) -> AuthConfig:
    """Validate configuration parameters and return AuthConfig instance.

    Args:
        **kwargs: Configuration parameters

    Returns:
        Validated AuthConfig instance

    Raises:
        ValueError: If any configuration parameter is invalid
    """
    try:
        return AuthConfig(**kwargs)
    except PydanticValidationError as e:
        # Extract detailed error messages from Pydantic validation error
        error_messages = []
        for error in e.errors():
            field = ".".join(str(loc) for loc in error["loc"])
            message = error["msg"]
            error_messages.append(f"{field}: {message}")

        detailed_message = "; ".join(error_messages)
        raise ValueError(f"Configuration validation failed: {detailed_message}") from e
    except Exception as e:
        # Handle other unexpected errors
        raise ValueError(f"Configuration validation failed: {str(e)}") from e
