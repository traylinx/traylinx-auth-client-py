#!/usr/bin/env python3
"""
Simple A2A Extension Demo (No external dependencies)
"""

import sys

sys.path.insert(0, ".")

from traylinx_auth_client import (
    TraylinxAuthClient,
    get_a2a_request_headers,
    validate_dual_auth_request,
    detect_auth_mode,
)


def demo_a2a_extension():
    print("🚀 TraylinxAuth A2A Extension Demo\n")

    # Create a mock client for demonstration
    client = TraylinxAuthClient()
    client.agent_user_id = "demo-agent-123"
    client._agent_secret_token = "demo-token-456"
    client._token_expiration = 9999999999  # Far future

    print("🔹 1. Generate A2A Headers (Bearer Token Format)")
    a2a_headers = client.get_a2a_headers()
    print(f"   A2A Headers: {a2a_headers}")
    print("   ✅ Perfect for A2A SDK integration!\n")

    print("🔹 2. Generate Legacy Headers (Custom Format)")
    legacy_headers = client.get_agent_request_headers()
    print(f"   Legacy Headers: {legacy_headers}")
    print("   ✅ Existing code still works!\n")

    print("🔹 3. Dual Authentication Validation")

    # Test Bearer token detection (without actual validation)
    bearer_request = {
        "Authorization": "Bearer demo-token-456",
        "X-Agent-User-Id": "demo-agent-123",
    }
    mode = client.detect_auth_mode(bearer_request)
    print(
        f"   Bearer Token Request: Mode={mode} (validation would check with auth service)"
    )

    # Test custom header detection
    custom_request = {
        "X-Agent-Secret-Token": "demo-token-456",
        "X-Agent-User-Id": "demo-agent-123",
    }
    mode = client.detect_auth_mode(custom_request)
    print(
        f"   Custom Header Request: Mode={mode} (validation would check with auth service)"
    )

    # Test case-insensitive headers
    mixed_case_request = {
        "AUTHORIZATION": "Bearer demo-token-456",
        "x-agent-user-id": "demo-agent-123",
    }
    mode = client.detect_auth_mode(mixed_case_request)
    print(
        f"   Mixed Case Request: Mode={mode} (validation would check with auth service)"
    )
    print("   ✅ Handles both formats seamlessly!\n")

    print("🔹 4. Migration Path")
    print("   Phase 1: Enable dual validation on servers")
    print("   Phase 2: Migrate clients to use get_a2a_headers()")
    print("   Phase 3: Monitor with detect_auth_mode()")
    print("   Phase 4: Switch to A2A-only when ready")
    print("   ✅ Smooth migration guaranteed!\n")

    print("🔹 5. Usage Examples")
    print("   # Consumer Agent (calling others)")
    print("   headers = client.get_a2a_headers()")
    print("   response = requests.post(url, headers=headers, json=data)")
    print()
    print("   # Provider Agent (receiving calls)")
    print("   @require_dual_auth")
    print("   def my_endpoint(request):")
    print("       return process_request(request)")
    print("   ✅ Simple and powerful!\n")

    print("🎉 Demo Complete!")
    print("\n📋 Key Benefits:")
    print("✅ Drop-in A2A compatibility")
    print("✅ Full backward compatibility")
    print("✅ Dual authentication support")
    print("✅ Case-insensitive headers")
    print("✅ Smooth migration path")
    print("✅ Zero breaking changes")


if __name__ == "__main__":
    demo_a2a_extension()
