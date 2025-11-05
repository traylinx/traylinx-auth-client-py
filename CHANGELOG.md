# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-09

### Added
- **Agent-to-Agent (A2A) Protocol Support**: Full implementation of Google's A2A Protocol for seamless agent communication
  - `get_a2a_headers()` method for A2A-compliant Bearer token format
  - `validate_a2a_request()` method supporting dual-mode authentication (Bearer + custom headers)
  - `detect_auth_mode()` for automatic authentication format detection
  - `@require_dual_auth` FastAPI decorator for flexible endpoint protection
  - JSON-RPC methods: `rpc_call()`, `rpc_introspect_token()`, `rpc_get_capabilities()`, `rpc_health_check()`
  - Full backward compatibility with existing custom header format
  - Migration-friendly design supporting gradual A2A adoption
- **Comprehensive Input Validation**: Added Pydantic-based configuration validation for all client parameters
  - Client ID format validation (alphanumeric, hyphens, underscores only)
  - URL format validation for API base URL
  - UUID format validation for agent user ID
  - Client secret security requirements validation
  - Timeout and retry parameter range validation
- **Custom Exception Hierarchy**: Implemented structured error handling with specific exception types
  - `TraylinxAuthError`: Base exception class with error codes and status codes
  - `AuthenticationError`: For authentication failures and credential issues
  - `TokenExpiredError`: For token expiration scenarios
  - `NetworkError`: For network connectivity and timeout issues
  - `ValidationError`: For input validation failures
- **Enhanced Error Handling**: Comprehensive HTTP error code handling with meaningful messages
  - Specific handling for 401 (authentication), 429 (rate limiting), 5xx (server errors)
  - Detailed error context and debugging information
  - Network exception handling (timeouts, connection errors, DNS failures)
- **Timeout and Retry Logic**: Robust network resilience features
  - Configurable timeout settings (default 30 seconds)
  - Exponential backoff retry strategy for transient failures
  - Connection pooling with HTTP session reuse
  - Automatic retry for rate limits and server errors
- **Production Readiness Features**:
  - Thread-safe token management with proper locking
  - Configurable logging without exposing sensitive data
  - Request timing and performance monitoring capabilities
  - Secure credential handling and memory management
- **Enhanced Package Configuration**:
  - Updated Python version support to >=3.8 (expanded from >=3.11)
  - Comprehensive package metadata with classifiers and keywords
  - MIT License inclusion
  - Proper dependency management (removed unused pyjwt)

### Changed
- **Backward Compatible API**: All existing public methods maintain the same signatures and behavior
- **Improved Token Management**: Enhanced caching and refresh logic while maintaining existing functionality
- **Enhanced Documentation**: Expanded README with comprehensive usage examples and troubleshooting

### Security
- **Input Sanitization**: All configuration parameters are validated to prevent injection attacks
- **Credential Protection**: Tokens and secrets are never logged or exposed in error messages
- **Secure Defaults**: HTTPS enforcement and proper certificate validation
- **Memory Safety**: Secure handling of sensitive data in memory

### Technical Details
- **Dependencies**: 
  - Added: `pydantic ^2.0.0` for input validation
  - Added: `urllib3` for enhanced retry logic
  - Maintained: `requests` for HTTP client functionality
- **Python Compatibility**: Supports Python 3.8, 3.9, 3.10, 3.11, 3.12+
- **Test Coverage**: Comprehensive test suite with >90% coverage
- **Performance**: Optimized connection pooling and token caching

### Migration Guide
This release is fully backward compatible. Existing code will continue to work without changes. New validation and error handling features are automatically enabled.

To take advantage of new configuration options:
```python
from traylinx_auth_client import TraylinxAuthClient

# New optional configuration parameters
client = TraylinxAuthClient(
    client_id="your_client_id",
    client_secret="your_client_secret", 
    api_base_url="https://your-api.com",
    agent_user_id="your-uuid",
    timeout=30,  # New: configurable timeout
    max_retries=3,  # New: configurable retry attempts
    retry_delay=1.0,  # New: configurable retry delay
    log_level="INFO"  # New: configurable logging
)
```

## [Unreleased]

### Planned
- TypeScript definitions for better IDE support
- Additional authentication methods
- Enhanced monitoring and metrics
- Performance optimizations

---

For more information about this release, see the [Requirements Document](https://github.com/your-org/traylinx-auth-client-py/blob/main/docs/requirements.md) and [Design Document](https://github.com/your-org/traylinx-auth-client-py/blob/main/docs/design.md).