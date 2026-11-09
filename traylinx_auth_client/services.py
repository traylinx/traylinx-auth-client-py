"""Deprecated introspector: legacy fail-closed bool contract, without logging secrets."""
from .token_manager import TokenManager
from .security import credential, valid_introspection, AUTH_RESPONSE, destination


class IntrospectionService:
    def __init__(self):
        self.token_manager = TokenManager()

    def validate_token(self, agent_secret_token, agent_user_id):
        if not credential(agent_secret_token) or not credential(agent_user_id) or len(agent_user_id) > 256:
            return False
        try:
            manager = self.token_manager
            destination(manager.api_base_url, base=True)
            response = manager._session.post(f"{manager.api_base_url.rstrip('/')}/oauth/agent/introspect",
                headers={"Authorization": f"Bearer {manager.get_access_token()}"},
                data={"agent_secret_token": agent_secret_token, "agent_user_id": agent_user_id},
                response_limit=AUTH_RESPONSE)
            response.raise_for_status()
            return valid_introspection(response.json(), agent_user_id)
        except Exception:
            return False
