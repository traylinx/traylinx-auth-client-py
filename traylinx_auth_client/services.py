# DEPRECATED: This file is deprecated and will be removed in a future version.
# Please use the TraylinxAuthClient class in client.py instead.

import os
import requests
from .token_manager import TokenManager


class IntrospectionService:
    def __init__(self):
        self.api_base_url = os.getenv("TRAYLINX_API_BASE_URL")
        self.token_manager = TokenManager()

    def validate_token(self, agent_secret_token: str, agent_user_id: str) -> bool:
        headers = {
            "Authorization": f"Bearer {self.token_manager.get_access_token()}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {
            "agent_secret_token": agent_secret_token,
            "agent_user_id": agent_user_id,
        }
        response = requests.post(
            f"{self.api_base_url}/oauth/agent/introspect", headers=headers, data=data
        )
        if response.status_code == 200:
            return response.json().get("active", False)
        return False
