"""Deprecated token manager. Keeps its legacy environment and attribute API."""
import os
import time
from threading import Lock
from .security import destination, token_state, AUTH_RESPONSE
from .transport import SecureSession


class TokenManager:
    _instance = None
    _lock = Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                obj = super().__new__(cls)
                obj.client_id = os.getenv("TRAYLINX_CLIENT_ID")
                obj.client_secret = os.getenv("TRAYLINX_CLIENT_SECRET")
                obj.api_base_url = os.getenv("TRAYLINX_API_BASE_URL")
                obj.access_token = obj.agent_secret_token = None
                obj.token_expiration = obj.agent_token_expiration = 0
                obj._generation = 0
                obj._session = SecureSession()
                cls._instance = obj
        return cls._instance

    def _fetch_tokens(self, kind="access"):
        generation = self._generation
        with self._lock:
            expiry = self.agent_token_expiration if kind == "agent" else self.token_expiration
            token = self.agent_secret_token if kind == "agent" else self.access_token
            if token and (expiry > time.time() or self._generation != generation):
                return
            started = time.time()
            try:
                destination(self.api_base_url, base=True)
                response = self._session.post(f"{self.api_base_url.rstrip('/')}/oauth/token",
                    data={"grant_type": "client_credentials", "client_id": self.client_id,
                          "client_secret": self.client_secret, "scope": "a2a"},
                    response_limit=AUTH_RESPONSE)
                response.raise_for_status()
                values = token_state(response.json(), started)
                self.access_token, self.agent_secret_token, self.token_expiration, self.agent_token_expiration = values
                self._generation += 1
            except Exception:
                self.access_token = self.agent_secret_token = None
                self.token_expiration = self.agent_token_expiration = 0
                from .exceptions import AuthenticationError
                raise AuthenticationError("Token exchange failed") from None

    def get_access_token(self):
        self._fetch_tokens("access")
        return self.access_token

    def get_agent_secret_token(self):
        self._fetch_tokens("agent")
        return self.agent_secret_token
