# Traylinx Auth Client (Python) - Implementation Plan

**Objective:** Create a robust, well-tested, and easy-to-use Python library that handles all aspects of Traylinx Sentinel A2A authentication for Python-based agents.

---

### **Phase 1: Core Logic & Project Scaffolding**

This phase focuses on setting up the project and implementing the central token-handling logic.

1.  **Initialize the Project Structure:**
    *   Create the standard Python package structure within the `traylinx_auth_client_py` directory.
    *   This includes creating a `traylinx_auth_client/` sub-directory for the source code and a `tests/` directory.
    *   Create a `pyproject.toml` file to manage project metadata and dependencies (`requests`, `fastapi`).

2.  **Implement the `TokenManager` (Internal Class):**
    *   **Goal:** This class will be the heart of the library, responsible for fetching, caching, and refreshing tokens.
    *   **Implementation:**
        *   It will be a singleton to ensure only one instance manages tokens for the entire application.
        *   It will read the `TRAYLINX_CLIENT_ID`, `TRAYLINX_CLIENT_SECRET`, and `TRAYLINX_API_BASE_URL` from environment variables.
        *   It will have a private method, `_fetch_tokens()`, that makes a `POST` request to the `/oauth/token` endpoint with the `client_credentials` grant type.
        *   It will cache the `access_token`, `agent_secret_token`, and their expiration time in memory.
        *   It will expose public methods like `get_access_token()` and `get_agent_secret_token()`. These methods will automatically check if the cached tokens are expired and call `_fetch_tokens()` to refresh them if necessary.

3.  **Implement the `IntrospectionService` (Internal Class):**
    *   **Goal:** This class will handle the validation of incoming tokens.
    *   **Implementation:**
        *   It will use the `TokenManager` to get the receiving agent's own `access_token` for authorization.
        *   It will have a method, `validate_token(agent_secret_token, agent_user_id)`, that makes a `POST` request to the `/oauth/agent/introspect` endpoint.
        *   It will return `True` if the token is active and valid, and `False` otherwise.

---

### **Phase 2: Public API for Developers**

This phase focuses on creating the simple, developer-friendly functions and decorators that agents will use.

1.  **Implement `get_request_headers()`:**
    *   **Goal:** Provide a one-line function for developers to get the required headers for making a secure A2A request.
    *   **Implementation:**
        *   This function will use the `TokenManager` to get the current `access_token` and `agent_secret_token`.
        *   It will read the `TRAYLINX_AGENT_USER_ID` from an environment variable.
        *   It will return a dictionary containing the `Authorization`, `X-Agent-Secret-Token`, and `X-Agent-User-Id` headers.

2.  **Implement the `@require_a2a_auth` Decorator:**
    *   **Goal:** Provide a simple, elegant way to protect FastAPI endpoints.
    *   **Implementation:**
        *   The decorator will extract the three required headers from the incoming request.
        *   It will use the `IntrospectionService` to validate the incoming `agent_secret_token`.
        *   If validation is successful, it will allow the request to proceed to the route handler.
        *   If validation fails, it will immediately return a `401 Unauthorized` HTTP error, stopping the request.

---

### **Phase 3: Testing & Packaging**

This phase ensures the library is reliable and ready for distribution.

1.  **Write Unit Tests (using `pytest` and `requests-mock`):**
    *   Test the `TokenManager`'s caching and token refresh logic.
    *   Test the `IntrospectionService`'s validation logic.
    *   Test the `get_request_headers()` function to ensure it constructs headers correctly.
    *   Test the `@require_a2a_auth` decorator in isolation, mocking the introspection call for both success and failure cases.

2.  **Write an Integration Test:**
    *   This test will simulate a real-world scenario.
    *   It will create a simple FastAPI application with a protected endpoint.
    *   It will use `get_request_headers()` to make a request to that endpoint.
    *   It will mock the `scoutica_auth_service` API to test the full, end-to-end flow.

3.  **Finalize Packaging:**
    *   Complete the `pyproject.toml` file with all the necessary metadata to make the package installable via `pip` and publishable to a package repository like PyPI.
