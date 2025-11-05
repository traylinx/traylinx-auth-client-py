#!/usr/bin/env python3
"""
Example: Using TraylinxAuth A2A Extension

This example demonstrates how to use the enhanced TraylinxAuth client
with A2A (Agent2Agent) Protocol support.
"""

import asyncio
from fastapi import FastAPI, Request, HTTPException
from traylinx_auth_client import (
    TraylinxAuthClient,
    get_a2a_request_headers,
    validate_dual_auth_request,
    require_dual_auth,
    detect_auth_mode,
)


# Example 1: Consumer Agent (Calling other agents)
def example_consumer_agent():
    """Example of using TraylinxAuth as an A2A consumer"""
    print("🔹 Example 1: Consumer Agent")

    # Initialize client
    client = TraylinxAuthClient(
        client_id="your-client-id",
        client_secret="your-client-secret",
        api_base_url="https://auth.makakoo.com/api",
    )

    # Get A2A-compatible headers (Bearer token format)
    a2a_headers = client.get_a2a_headers()
    print(f"A2A Headers: {a2a_headers}")

    # Get legacy headers (custom format) - still works!
    legacy_headers = client.get_agent_request_headers()
    print(f"Legacy Headers: {legacy_headers}")

    print("✅ Consumer agent example complete\n")


# Example 2: Provider Agent (Receiving requests)
app = FastAPI()


@app.post("/api/process")
@require_dual_auth  # Accepts both Bearer tokens AND custom headers
async def process_data(request: Request):
    """Example endpoint that accepts both auth formats"""

    # Detect which auth mode was used
    auth_mode = detect_auth_mode(dict(request.headers))

    return {
        "message": "Data processed successfully",
        "auth_mode": auth_mode,
        "agent_id": request.headers.get("x-agent-user-id"),
    }


@app.post("/api/a2a-only")
async def a2a_only_endpoint(request: Request):
    """Example endpoint that only accepts A2A Bearer tokens"""

    # Manual validation for A2A-only endpoints
    if not validate_dual_auth_request(dict(request.headers)):
        raise HTTPException(status_code=401, detail="A2A authentication required")

    auth_mode = detect_auth_mode(dict(request.headers))
    if auth_mode != "bearer":
        raise HTTPException(
            status_code=400, detail="Bearer token required for this endpoint"
        )

    return {"message": "A2A-only endpoint accessed", "auth_mode": auth_mode}


def example_provider_agent():
    """Example of setting up a provider agent"""
    print("🔹 Example 2: Provider Agent")
    print("FastAPI app configured with dual authentication support")
    print("- /api/process: Accepts both Bearer tokens and custom headers")
    print("- /api/a2a-only: Requires Bearer tokens only")
    print("✅ Provider agent example complete\n")


# Example 3: Migration Scenarios
def example_migration_scenarios():
    """Examples of different migration scenarios"""
    print("🔹 Example 3: Migration Scenarios")

    client = TraylinxAuthClient()

    # Scenario 1: Existing agent with custom headers
    print("Scenario 1: Legacy agent calling new A2A-enabled service")
    legacy_headers = {
        "X-Agent-Secret-Token": "legacy-token-123",
        "X-Agent-User-Id": "agent-456",
    }
    is_valid = client.validate_a2a_request(legacy_headers)
    mode = client.detect_auth_mode(legacy_headers)
    print(f"  Legacy headers valid: {is_valid}, Mode: {mode}")

    # Scenario 2: New A2A agent with Bearer tokens
    print("Scenario 2: A2A agent calling legacy service")
    a2a_headers = {
        "Authorization": "Bearer a2a-token-789",
        "X-Agent-User-Id": "agent-456",
    }
    is_valid = client.validate_a2a_request(a2a_headers)
    mode = client.detect_auth_mode(a2a_headers)
    print(f"  A2A headers valid: {is_valid}, Mode: {mode}")

    # Scenario 3: Mixed case headers (real-world scenario)
    print("Scenario 3: Mixed case headers from different HTTP clients")
    mixed_headers = {
        "AUTHORIZATION": "Bearer mixed-token-abc",
        "x-agent-user-id": "agent-456",
    }
    is_valid = client.validate_a2a_request(mixed_headers)
    mode = client.detect_auth_mode(mixed_headers)
    print(f"  Mixed case headers valid: {is_valid}, Mode: {mode}")

    print("✅ Migration scenarios example complete\n")


# Example 4: Best Practices
def example_best_practices():
    """Best practices for using A2A extension"""
    print("🔹 Example 4: Best Practices")

    print("1. Use environment variables for configuration:")
    print("   export TRAYLINX_CLIENT_ID='your-client-id'")
    print("   export TRAYLINX_CLIENT_SECRET='your-client-secret'")
    print("   export TRAYLINX_API_BASE_URL='https://auth.makakoo.com/api'")
    print("   export TRAYLINX_AGENT_USER_ID='your-agent-id'")

    print("\n2. For new A2A agents, use Bearer token format:")
    print("   headers = client.get_a2a_headers()")

    print("\n3. For backward compatibility, use dual validation:")
    print("   @require_dual_auth  # Accepts both formats")

    print("\n4. For gradual migration:")
    print("   - Start with dual validation on servers")
    print("   - Migrate clients to Bearer tokens over time")
    print("   - Eventually switch to A2A-only validation")

    print("\n5. Monitor auth modes for migration progress:")
    print("   auth_mode = detect_auth_mode(headers)")
    print("   # Log metrics to track Bearer vs custom usage")

    print("✅ Best practices example complete\n")


if __name__ == "__main__":
    print("🚀 TraylinxAuth A2A Extension Examples\n")

    example_consumer_agent()
    example_provider_agent()
    example_migration_scenarios()
    example_best_practices()

    print("🎉 All examples complete!")
    print("\n📚 Next Steps:")
    print("1. Set up your environment variables")
    print("2. Start with dual authentication on your servers")
    print("3. Gradually migrate clients to use get_a2a_headers()")
    print("4. Monitor usage with detect_auth_mode()")
    print("5. Eventually switch to A2A-only endpoints when ready")
