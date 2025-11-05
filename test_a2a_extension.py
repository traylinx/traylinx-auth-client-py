#!/usr/bin/env python3
"""
Test script for TraylinxAuth A2A Extension
"""

import os
import sys

sys.path.insert(0, ".")

from traylinx_auth_client import (
    TraylinxAuthClient,
    get_a2a_request_headers,
    validate_dual_auth_request,
    detect_auth_mode,
)


def test_a2a_headers():
    """Test A2A header generation"""
    print("Testing A2A header generation...")

    # Mock client for testing
    client = TraylinxAuthClient()
    client.agent_user_id = "test-agent-123"
    client._agent_secret_token = "test-token-456"
    client._token_expiration = 9999999999  # Far future

    # Test A2A headers
    headers = client.get_a2a_headers()
    print(f"A2A Headers: {headers}")

    assert "Authorization" in headers
    assert headers["Authorization"].startswith("Bearer ")
    assert headers["X-Agent-User-Id"] == "test-agent-123"
    print("✅ A2A headers test passed")


def test_dual_validation():
    """Test dual authentication validation"""
    print("\nTesting dual authentication validation...")

    client = TraylinxAuthClient()

    # Test Bearer token format
    bearer_headers = {
        "Authorization": "Bearer test-token",
        "X-Agent-User-Id": "test-agent",
    }
    mode = client.detect_auth_mode(bearer_headers)
    print(f"Bearer token mode: {mode}")
    assert mode == "bearer"

    # Test custom header format
    custom_headers = {
        "X-Agent-Secret-Token": "test-token",
        "X-Agent-User-Id": "test-agent",
    }
    mode = client.detect_auth_mode(custom_headers)
    print(f"Custom header mode: {mode}")
    assert mode == "custom"

    # Test no auth
    no_auth_headers = {"Content-Type": "application/json"}
    mode = client.detect_auth_mode(no_auth_headers)
    print(f"No auth mode: {mode}")
    assert mode == "none"

    print("✅ Dual validation test passed")


def test_case_insensitive():
    """Test case-insensitive header handling"""
    print("\nTesting case-insensitive header handling...")

    client = TraylinxAuthClient()

    # Test mixed case headers
    mixed_headers = {
        "AUTHORIZATION": "Bearer test-token",
        "x-agent-user-id": "test-agent",
    }
    mode = client.detect_auth_mode(mixed_headers)
    print(f"Mixed case mode: {mode}")
    assert mode == "bearer"

    print("✅ Case-insensitive test passed")


def test_backward_compatibility():
    """Test that existing functionality still works"""
    print("\nTesting backward compatibility...")

    client = TraylinxAuthClient()
    client.agent_user_id = "test-agent-123"
    client._agent_secret_token = "test-token-456"
    client._token_expiration = 9999999999  # Far future

    # Test existing method still works
    legacy_headers = client.get_agent_request_headers()
    print(f"Legacy headers: {legacy_headers}")

    assert "X-Agent-Secret-Token" in legacy_headers
    assert "X-Agent-User-Id" in legacy_headers
    assert "Authorization" not in legacy_headers  # Should not have Bearer token

    print("✅ Backward compatibility test passed")


if __name__ == "__main__":
    print("🚀 Testing TraylinxAuth A2A Extension\n")

    try:
        test_a2a_headers()
        test_dual_validation()
        test_case_insensitive()
        test_backward_compatibility()

        print("\n🎉 All tests passed! A2A extension is working correctly.")
        print("\n📋 Summary:")
        print("✅ A2A Bearer token headers generation")
        print("✅ Dual authentication mode detection")
        print("✅ Case-insensitive header handling")
        print("✅ Backward compatibility maintained")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
