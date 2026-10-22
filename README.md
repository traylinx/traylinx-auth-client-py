# Traylinx Auth Client (Python)

Sentinel Pass authentication for Traylinx agent-to-agent communication.

> **1.1.0rc1: opt-in release candidate. Not qualified for production deployment.**
> Existing stable installations are not upgraded by this release.

## Install

Requires **Python >=3.11,<4**. Runtime dependencies, installed automatically:
Requests `>=2.34.2,<3`, FastAPI `>=0.161.0,<1`, Pydantic `>=2.14.1,<3`.

```bash
python -m pip install 'traylinx-auth-client==1.1.0rc1'
```

Pin the prerelease explicitly. Unpinned stable installs are not the opt-in path.

## Configure

Supply these values securely through your application's environment or secret manager:

| Variable | Meaning |
|---|---|
| `TRAYLINX_CLIENT_ID` | Sentinel OAuth client id |
| `TRAYLINX_CLIENT_SECRET` | Sentinel OAuth client secret |
| `TRAYLINX_API_BASE_URL` | Trusted Sentinel HTTPS base URL |
| `TRAYLINX_AGENT_USER_ID` | Agent UUID |

These identify the calling/verifying agent, not credentials for websites it visits.
Do not commit credentials or include them in logs.

## Call a trusted agent

```python
from traylinx_auth_client import make_a2a_request

# Fixed application-approved destination, not an untrusted input URL.
def fetch_status():
    return make_a2a_request("GET", "https://agent.example/status")

def submit_task():
    return make_a2a_request(
        "POST", "https://agent.example/tasks",
        json={"operation": "inspect"}, timeout=30,
    )
```

Allowed request options: `headers`, `params`, `data`, `json` and `timeout`.
Timeouts are seconds. Authentication, host and cookie header overrides are rejected.
POST is not automatically replayed.

## Verify incoming proof

`require_a2a_auth` and `validate_a2a_request` accept the custom header pair
`X-Agent-Secret-Token` / `X-Agent-User-Id`. `require_dual_auth` and
`validate_dual_auth_request` additionally accept a **Sentinel agent pass** in
`Authorization: Bearer ...`, with `X-Agent-User-Id`.
This does not validate ordinary user bearer tokens or arbitrary OAuth tokens.

For resource-level authorization, use verified introspection metadata rather than
trusting an agent id supplied in headers:

```python
from traylinx_auth_client import TraylinxAuthClient

client = TraylinxAuthClient()  # Reads the environment above.

def verify_pass(pass_value, claimed_agent_id):
    principal = client.introspect_token(pass_value, claimed_agent_id)
    if not principal["active"]:
        return None
    # Caller must authorize principal["agent_id"] for the requested resource.
    return principal
```

Validate duplicate/mixed headers before extracting proof in custom middleware.
Do not invoke business logic if introspection fails or raises.
`validate_token(pass_value, agent_id)` remains the boolean API.
`get_agent_request_headers()` returns custom agent headers;
`get_a2a_request_headers()` returns agent bearer headers.
`get_request_headers()` is **Sentinel-only**, not incoming agent proof.

Constructor options include `timeout`, `max_retries`, `retry_delay`, `cache_tokens`,
`agent_token_ttl_seconds` and `refresh_skew_seconds`. Set `agent_token_ttl_seconds`
only when the server's pass lifetime has been verified independently.

The client is synchronous. FastAPI authentication decorators bridge blocking I/O
through Starlette's thread pool and wrap async endpoints that accept a `Request`.
Do not call the synchronous client directly on an event loop. Coroutine cancellation
does not forcibly stop an in-flight Requests operation; see the transport limits below.

## Security and compatibility

- This is **Sentinel Pass authentication**, not a full A2A task-protocol SDK.
- HTTPS with certificate verification is required. Credential-bearing redirects,
  URL userinfo, fragments, duplicate/mixed authentication and credential overrides
  are rejected. Request/decoded-response bounds are 4 MiB, or 64 KiB for auth responses.
- Only eligible GET/HEAD operations in the configured client retry path may retry.
  Token exchanges, introspection, RPC and other writes are never automatically replayed.
  The high-level remote-agent helper does not promise automatic retries.
- Access tokens stay with Sentinel. Remote-agent helpers send an agent pass and
  agent id, not the Sentinel access token. Never send these credentials to an
  arbitrary URL supplied by a user or scraped page; destinations must be trusted
  application configuration. This SDK is not an SSRF policy engine.
- Introspection validates agent binding, scope, active status and expiry. A valid
  pass authenticates a principal; the application must still authorize access to
  resources and enforce ownership, grants and quotas.
- Middleware rejects invalid/missing proof with 401 and fails closed with 503 when
  verification is unavailable. Never fall back to another principal after failed proof.
- Access and pass lifetimes are independent. If the server does not return
  `agent_secret_token_expires_in`, a pass is not reused across sequential operations
  unless an operator supplies a verified pass lifetime. Do not guess the lifetime.
- Header helpers return credentials to the caller. If you use your own HTTP client,
  TLS, redirects, timeouts, safe destinations and secret-free logging become your
  responsibility. Do not print or persist returned headers or tokens.

Existing helper entry points remain, but HTTPS enforcement, runtime floors,
stricter verification and error behavior are intentional migration changes.
See [HARDENING.md](HARDENING.md) for the full contract and transport limitations.

## Qualification

Tests use synthetic credentials and owned loopback HTTPS fixtures. Local tests do
not establish production readiness. Before production adoption, independently
review the integration, verify deployed server deactivation/revocation and token
lifetimes, and qualify platform support, throughput and cancellation behavior.
See [QUALIFICATION.md](QUALIFICATION.md) for measured coverage and remaining gates.

Publishing this candidate does not change any server, install it into an existing
application, or replace ordinary user-token authentication.

## License

MIT. See [LICENSE](LICENSE).

## Development

```bash
poetry install --with dev
poetry run pytest
```
