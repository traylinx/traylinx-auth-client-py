from .main import (
    get_request_headers,
    get_agent_request_headers,
    require_a2a_auth,
    a2a_request,
    make_a2a_request,
    validate_a2a_request,
    # A2A Extension Functions
    get_a2a_request_headers,
    validate_dual_auth_request,
    detect_auth_mode,
    require_dual_auth,
)
from .client import TraylinxAuthClient
from .config import AuthConfig
from .exceptions import (
    TraylinxAuthError,
    AuthenticationError,
    TokenExpiredError,
    NetworkError,
    ValidationError,
)

__version__ = "1.0.3"

__all__ = [
    # Existing functions
    "get_request_headers",
    "get_agent_request_headers",
    "require_a2a_auth",
    "a2a_request",
    "make_a2a_request",
    "validate_a2a_request",
    "TraylinxAuthClient",
    # A2A Extension functions
    "get_a2a_request_headers",
    "validate_dual_auth_request",
    "detect_auth_mode",
    "require_dual_auth",
    # Configuration and validation
    "AuthConfig",
    # Exception classes
    "TraylinxAuthError",
    "AuthenticationError",
    "TokenExpiredError",
    "NetworkError",
    "ValidationError",
    # Version
    "__version__",
]
