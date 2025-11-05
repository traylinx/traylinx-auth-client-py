# DEPRECATED: This file is deprecated and will be removed in a future version.
# Please use the TraylinxAuthClient class in client.py instead.

import os
import requests
import time
from threading import Lock


class TokenManager:
    _instance = None
    _lock = Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(TokenManager, cls).__new__(cls)
                cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self.client_id = os.getenv("TRAYLINX_CLIENT_ID")
        self.client_secret = os.getenv("TRAYLINX_CLIENT_SECRET")
        self.api_base_url = os.getenv("TRAYLINX_API_BASE_URL")
        self.access_token = None
        self.agent_secret_token = None
        self.token_expiration = 0
        self._initialized = True

    def _fetch_tokens(self):
        with self._lock:
            # Double-check if another thread has already fetched the tokens
            if self.token_expiration > time.time():
                return

            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "a2a",
            }
            response = requests.post(f"{self.api_base_url}/oauth/token", data=data)
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data["access_token"]
            self.agent_secret_token = token_data["agent_secret_token"]
            self.token_expiration = time.time() + token_data["expires_in"]

    def get_access_token(self):
        if self.token_expiration < time.time():
            self._fetch_tokens()
        return self.access_token

    def get_agent_secret_token(self):
        if self.token_expiration < time.time():
            self._fetch_tokens()
        return self.agent_secret_token
