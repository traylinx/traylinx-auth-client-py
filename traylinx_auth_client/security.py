"""Shared credential boundary. No network calls and no credential-bearing errors."""
import math
import re
import time
from urllib.parse import urlsplit
from .exceptions import ValidationError, AuthenticationError

MAX_RESPONSE = 4 * 1024 * 1024
AUTH_RESPONSE = 64 * 1024
SECRET_HEADERS = {"authorization", "proxy-authorization", "x-agent-secret-token", "x-agent-user-id", "host", "cookie"}

def destination(value, base=False):
    try:
        u = urlsplit(value)
        _ = u.port
        if not isinstance(value, str) or not value.startswith("https://") or re.search(r"[\x00-\x20\x7f\\]", value) or u.scheme != "https" or not u.hostname or u.username is not None or u.password is not None or u.fragment or (base and u.query):
            raise ValueError()
        return u
    except (ValueError, TypeError, AttributeError):
        raise ValidationError("Invalid HTTPS destination", error_code="UNSAFE_DESTINATION") from None

def credential(value):
    return isinstance(value, str) and 0 < len(value) <= 16384 and not re.search(r"[\s,]", value)

def normal_headers(headers):
    if not hasattr(headers, "items"):
        return None
    out = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str) or re.search(r"[\r\n]", key + value) or key.lower() in out:
            return None
        out[key.lower()] = value
    return out

def credentials_from(headers, dual=True):
    h = normal_headers(headers)
    if h is None or not credential(h.get("x-agent-user-id")) or len(h["x-agent-user-id"]) > 256:
        return None
    if "authorization" in h and "x-agent-secret-token" in h:
        return None
    token = h.get("x-agent-secret-token")
    if credential(token):
        return token, h["x-agent-user-id"], "custom"
    auth = h.get("authorization", "")
    if dual and re.fullmatch(r"Bearer [^\s,]+", auth) and credential(auth[7:]):
        return auth[7:], h["x-agent-user-id"], "bearer"
    return None

def outbound_options(options, default_timeout=30):
    if set(options) - {"headers", "params", "data", "json", "timeout"}:
        raise ValidationError("Unsafe or unsupported request option", error_code="UNSAFE_OPTIONS")
    headers = normal_headers(options.get("headers", {}))
    if headers is None or set(headers) & SECRET_HEADERS:
        raise ValidationError("Authentication headers cannot be overridden", error_code="AUTH_HEADER_OVERRIDE")
    timeout = options.get("timeout", default_timeout)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise ValidationError("Invalid request timeout")
    return dict(options, headers=dict(headers), timeout=timeout)

def token_state(data, started, configured_ttl=None, skew=30):
    def ttl(value):
        return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 < value <= 2678400
    if not isinstance(data, dict) or not credential(data.get("access_token")) or not credential(data.get("agent_secret_token")) or not ttl(data.get("expires_in")):
        raise AuthenticationError("Invalid token response", error_code="INVALID_TOKEN_RESPONSE")
    agent_ttl = data.get("agent_secret_token_expires_in", configured_ttl)
    if agent_ttl is not None and not ttl(agent_ttl):
        raise AuthenticationError("Invalid token expiry", error_code="INVALID_TOKEN_RESPONSE")
    def expires(seconds):
        return started + seconds - min(skew, seconds / 10)
    access_expiry = expires(data["expires_in"])
    agent_expiry = 0 if agent_ttl is None else expires(min(data["expires_in"], agent_ttl))
    if access_expiry <= time.time() or (agent_ttl is not None and agent_expiry <= time.time()):
        raise AuthenticationError("Token expired during exchange", error_code="INVALID_TOKEN_RESPONSE")
    return data["access_token"], data["agent_secret_token"], access_expiry, agent_expiry

def valid_introspection(data, agent_id):
    return (isinstance(data, dict) and data.get("active") is True and data.get("agent_id") == agent_id
            and data.get("is_active") is not False and isinstance(data.get("expires_at"), (int, float))
            and not isinstance(data["expires_at"], bool) and math.isfinite(data["expires_at"])
            and data["expires_at"] > time.time() and isinstance(data.get("scopes"), str)
            and "a2a" in data["scopes"].split())
