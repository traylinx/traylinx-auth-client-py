# Traylinx Auth Client (Python) - Design Specification (v2)

## 1. Overview

This document outlines the design for the Python version of the `traylinx_auth_client` library. This library will provide a comprehensive solution for agents written in Python to interact with the Traylinx authentication system, which uses a dual-token mechanism for security.

The library will handle two primary use cases:
1.  **Client-side Authentication:** Getting tokens and preparing headers for secure calls to other services.
2.  **Server-side Validation:** Protecting an agent's own API endpoints by validating incoming requests using the custom introspection flow.

## 2. Core Components

### 2.1. Configuration

The library will be configured via environment variables:
- `TRAYLINX_CLIENT_ID`: The agent's unique client ID.
- `TRAYLINX_CLIENT_SECRET`: The agent's client secret.
- `TRAYLINX_AGENT_USER_ID`: The agent's own user ID (UUID).
- `TRAYLINX_API_BASE_URL`: The base URL for the authentication service (e.g., `https://api.makakoo.com/ma-authentication-ms/v1/api`).

### 2.2. `TokenManager` (Internal)

A singleton class that will manage the lifecycle of the agent's tokens.
- It will fetch **both** the `access_token` and the `agent_secret_token` from the `/oauth/token` endpoint.
- It will cache these tokens in memory.
- It will automatically refresh the tokens before they expire.
- It will expose methods like `get_access_token()` and `get_agent_secret_token()` for internal library use.

## 3. Public API

### 3.1. Client-Side: `get_request_headers()`

This function is used when the agent needs to call another service. It provides all the necessary headers for the custom A2A authentication flow.

- **Signature:** `get_request_headers() -> dict`
- **Functionality:**
  - Retrieves a valid `access_token` and `agent_secret_token` from the internal `TokenManager`.
  - Retrieves the agent's own user ID from the `TRAYLINX_AGENT_USER_ID` environment variable.
  - Constructs and returns a dictionary of headers:
    ```python
    {
        'Authorization': 'Bearer <access_token>',
        'X-Agent-Secret-Token': '<agent_secret_token>',
        'X-Agent-User-Id': '<agent_user_id>'
    }
    ```
- **Example Usage:**
  ```python
  from traylinx_auth_client import get_request_headers
  import requests

  # Get all required headers in one call
  headers = get_request_headers()

  # Make a request to another agent
  response = requests.post("https://agent-b.com/api/v1/process", headers=headers)
  ```

### 3.2. Server-Side: `@require_a2a_auth` Decorator

This decorator is used to protect an agent's API endpoints.

- **Functionality:**
  1.  Extracts the caller's `access_token` from the `Authorization` header.
  2.  Extracts the caller's `agent_secret_token` from the `X-Agent-Secret-Token` header.
  3.  Extracts the caller's `agent_user_id` from the `X-Agent-User-Id` header.
  4.  Uses the library's own `TokenManager` to get the **receiving agent's own** `access_token`.
  5.  Calls the `POST /oauth/agent/introspect` endpoint. The call is authorized with the receiving agent's `access_token`. The body contains the `agent_secret_token` and `agent_user_id` of the **calling agent**.
  6.  Checks that the `active` field in the introspection response is `true`.
  7.  If valid, allows the request to proceed.
  8.  If invalid, it immediately returns a `401 Unauthorized` error.

- **Example Usage (FastAPI):**
  ```python
  from traylinx_auth_client import require_a2a_auth
  from fastapi import FastAPI

  app = FastAPI()

  @app.post("/some_protected_endpoint")
  @require_a2a_auth
  async def protected_route():
      # This code only runs if the calling agent is successfully validated
      return {"message": "This is a protected resource."}
  ```

### 3.3. Introspection Service

The introspection service will be a class that can be used to validate an agent's secret token.

- **Signature:** `IntrospectionService.validate(agent_secret_token: str, agent_user_id: str) -> bool`
- **Functionality:**
    - Uses the library's own `TokenManager` to get the **receiving agent's own** `access_token`.
    - Calls the `POST /oauth/agent/introspect` endpoint. The call is authorized with the receiving agent's `access_token`. The body contains the `agent_secret_token` and `agent_user_id` of the **calling agent**.
    - Checks that the `active` field in the introspection response is `true`.
    - Returns `True` if the token is valid, `False` otherwise.