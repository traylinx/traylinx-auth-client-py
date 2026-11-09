import socket
import pytest

@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    original = socket.getaddrinfo
    def local_only(host, *args, **kwargs):
        if host not in ("localhost", "127.0.0.1", "::1", None):
            raise AssertionError("Unit tests must not access external network")
        return original(host, *args, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", local_only)
